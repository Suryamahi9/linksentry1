"use client";

import { useEffect, useRef } from "react";
import * as THREE from "three";

interface ScanField3DProps {
  pingUrl: string | null;
}

// mulberry32 — tiny deterministic PRNG so the "recent scans" layout is stable across reloads
function mulberry32(seed: number) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashString(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function latLonToVec3(lat: number, lon: number, radius: number): THREE.Vector3 {
  const phi = ((90 - lat) * Math.PI) / 180;
  const theta = ((lon + 180) * Math.PI) / 180;
  return new THREE.Vector3(
    -(radius * Math.sin(phi) * Math.cos(theta)),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
}

const RADIUS = 1.6;
const COLOR_PHOSPHOR = 0x4fe8c4;
const COLOR_AMBER = 0xf5a623;
const COLOR_DANGER = 0xe4573d;
const COLOR_GRID = 0x1e2330;
const NODE_COUNT = 36;
const ARC_COUNT = 14;

export default function ScanField3D({ pingUrl }: ScanField3DProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const pendingPingRef = useRef<string | null>(null);

  // Queue pings from outside the effect lifecycle
  useEffect(() => {
    if (pingUrl) {
      pendingPingRef.current = pingUrl;
    }
  }, [pingUrl]);

  useEffect(() => {
    if (!mountRef.current) return;

    const reducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    const container = mountRef.current;
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0e14);

    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 50);
    camera.position.set(0, 0.35, 4.6);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    const root = new THREE.Group();
    root.rotation.y = -0.6;
    scene.add(root);

    // --- Globe mesh ---
    const globeGeo = new THREE.IcosahedronGeometry(RADIUS, 2);
    const globeWire = new THREE.LineSegments(
      new THREE.WireframeGeometry(globeGeo),
      new THREE.LineBasicMaterial({
        color: COLOR_GRID,
        transparent: true,
        opacity: 0.55,
      })
    );
    root.add(globeWire);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(RADIUS * 1.004, 48, 24),
      new THREE.MeshBasicMaterial({
        color: COLOR_PHOSPHOR,
        transparent: true,
        opacity: 0.045,
        wireframe: true,
      })
    );
    root.add(atmosphere);

    // --- Equator + a few latitude rings as fiducials ---
    const ringMat = new THREE.LineBasicMaterial({
      color: COLOR_PHOSPHOR,
      transparent: true,
      opacity: 0.1,
    });
    for (const lat of [0, 25, -25]) {
      const r = RADIUS * Math.cos((lat * Math.PI) / 180);
      const y = RADIUS * Math.sin((lat * Math.PI) / 180);
      const ring = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(
          Array.from({ length: 72 }, (_, i) => {
            const a = (i / 72) * Math.PI * 2;
            return new THREE.Vector3(Math.cos(a) * r, y, Math.sin(a) * r);
          })
        ),
        ringMat
      );
      root.add(ring);
    }

    // --- Deterministic "recent scan" activity: nodes + arcs ---
    const rand = mulberry32(0x1a7de5);
    const nodeMeshes: THREE.Mesh[] = [];
    const nodePositions: THREE.Vector3[] = [];

    const dotMat = new THREE.MeshBasicMaterial({ color: COLOR_PHOSPHOR });
    const dotGeo = new THREE.SphereGeometry(0.014, 12, 12);

    for (let i = 0; i < NODE_COUNT; i++) {
      const lat = rand() * 150 - 75;
      const lon = rand() * 360 - 180;
      const pos = latLonToVec3(lat, lon, RADIUS);
      const dot = new THREE.Mesh(dotGeo, dotMat);
      dot.position.copy(pos);
      dot.userData.baseState = rand() > 0.6 ? "amber" : "idle";
      if (dot.userData.baseState === "amber") {
        (dot.material as THREE.MeshBasicMaterial).color.setHex(COLOR_AMBER);
      }
      root.add(dot);
      nodeMeshes.push(dot);
      nodePositions.push(pos);
    }

    const arcMat = new THREE.LineBasicMaterial({
      color: COLOR_PHOSPHOR,
      transparent: true,
      opacity: 0.22,
    });

    for (let i = 0; i < ARC_COUNT; i++) {
      const a = Math.floor(rand() * NODE_COUNT);
      let b = Math.floor(rand() * NODE_COUNT);
      if (b === a) b = (b + 1) % NODE_COUNT;
      const p1 = nodePositions[a];
      const p2 = nodePositions[b];
      const mid = p1
        .clone()
        .add(p2)
        .multiplyScalar(0.5)
        .normalize()
        .multiplyScalar(RADIUS * 1.35);
      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
      const points = curve.getPoints(30);
      const arc = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(points),
        arcMat
      );
      root.add(arc);
    }

    // --- Ping rings (reused meshes) ---
    const PING_RINGS = 2;
    const pingRings: THREE.Mesh[] = [];
    const pingRingGeo = new THREE.RingGeometry(0.02, 0.06, 24);
    for (let i = 0; i < PING_RINGS; i++) {
      const m = new THREE.Mesh(
        pingRingGeo,
        new THREE.MeshBasicMaterial({
          color: COLOR_PHOSPHOR,
          transparent: true,
          opacity: 0,
          side: THREE.DoubleSide,
        })
      );
      // orient the ring to face outward from the sphere center
      root.add(m);
      pingRings.push(m);
    }

    // --- Background stars (static, tiny) ---
    const starGeo = new THREE.BufferGeometry();
    const starCount = 220;
    const starPos = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
      starPos[i * 3] = (Math.random() - 0.5) * 30;
      starPos[i * 3 + 1] = (Math.random() - 0.5) * 18;
      starPos[i * 3 + 2] = -8 - Math.random() * 6;
    }
    starGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
    const stars = new THREE.Points(
      starGeo,
      new THREE.PointsMaterial({
        color: 0x3a4456,
        size: 0.015,
        transparent: true,
        opacity: 0.6,
      })
    );
    scene.add(stars);

    // --- Ping handling ---
    const activePings: {
      ring: THREE.Mesh;
      startTime: number;
      origin: THREE.Vector3;
    }[] = [];

    function firePing(url: string) {
      const h = hashString(url);
      const randForPing = mulberry32(h);
      const targetLat = randForPing() * 140 - 70;
      const targetLon = randForPing() * 360 - 180;
      const targetPos = latLonToVec3(targetLat, targetLon, RADIUS);

      // find nearest node
      let nearest = 0;
      let nearestDist = Infinity;
      nodePositions.forEach((p, i) => {
        const d = p.distanceToSquared(targetPos);
        if (d < nearestDist) {
          nearestDist = d;
          nearest = i;
        }
      });

      const origin = nodePositions[nearest];
      if (pingRings.length) {
        activePings.push({ ring: pingRings[0], startTime: performance.now(), origin });
        if (pingRings.length > 1) {
          activePings.push({
            ring: pingRings[1],
            startTime: performance.now() + 160,
            origin,
          });
        }
        // flash the node
        const node = nodeMeshes[nearest];
        (node.material as THREE.MeshBasicMaterial).color.setHex(COLOR_PHOSPHOR);
        if (reducedMotion) {
          // reduced motion: just leave the node highlighted, no animation
          return;
        }
        setTimeout(() => {
          if ((node.material as THREE.MeshBasicMaterial).color.getHex() === COLOR_PHOSPHOR) {
            (node.material as THREE.MeshBasicMaterial).color.setHex(
              node.userData.baseState === "amber" ? COLOR_AMBER : COLOR_PHOSPHOR
            );
          }
        }, 1400);
      }
    }

    // --- Resize ---
    function resize() {
      const w = container.clientWidth;
      const h = container.clientHeight;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(container);

    // --- Render loop ---
    let raf = 0;
    let lastRender = performance.now();

    function renderFrame(now: number) {
      const dt = Math.min(0.05, (now - lastRender) / 1000);
      lastRender = now;

      root.rotation.y += dt * 0.08;

      // gentle node pulse (subtle, event=new-frame only)
      const pulse = Math.sin(now * 0.003) * 0.004 + 0.014;
      for (const n of nodeMeshes) {
        (n.scale as THREE.Vector3).setScalar(pulse);
      }

      // process pings
      if (pendingPingRef.current) {
        const url = pendingPingRef.current;
        pendingPingRef.current = null;
        firePing(url);
      }

      // advance active pings
      for (let i = activePings.length - 1; i >= 0; i--) {
        const p = activePings[i];
        const elapsed = now - p.startTime;
        if (elapsed > 1400) {
          p.ring.position.set(0, 0, 0);
          (p.ring.material as THREE.MeshBasicMaterial).opacity = 0;
          activePings.splice(i, 1);
          continue;
        }
        const t = elapsed / 1400;
        const scale = 0.02 + t * 7;
        p.ring.lookAt(p.origin.clone().multiplyScalar(4));
        p.ring.position.copy(p.origin);
        (p.ring.scale as THREE.Vector3).setScalar(scale * 4);
        (p.ring.material as THREE.MeshBasicMaterial).opacity = 0.9 * (1 - t);
      }

      renderer.render(scene, camera);
      if (!reducedMotion) {
        raf = requestAnimationFrame(renderFrame);
      }
    }

    if (reducedMotion) {
      // Static presentation — rotate once to a nice angle, render a single frame
      root.rotation.y = -0.6;
      renderer.render(scene, camera);
    } else {
      raf = requestAnimationFrame(renderFrame);
    }

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      renderer.dispose();
      if (renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  return (
    <div
      ref={mountRef}
      className="absolute inset-0"
      style={{ pointerEvents: "none" }}
      aria-hidden="true"
    />
  );
}