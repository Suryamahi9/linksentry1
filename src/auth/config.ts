import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";
import Nodemailer from "next-auth/providers/nodemailer";

// Prisma is optional — auth works without DB via JWT, but persistence
// (accounts, sessions, API keys, bulk jobs, reports) requires POSTGRES_URL.
let prisma: any = null;
let PrismaAdapter: any = null;
try {
  const mod = await import("@/lib/prisma").catch(() => null);
  prisma = mod?.prisma ?? null;
  if (prisma) {
    const adapterMod = await import("@auth/prisma-adapter").catch(() => null);
    PrismaAdapter = adapterMod?.PrismaAdapter ?? null;
  }
} catch {}

const providers: any[] = [];

if (process.env.EMAIL_SERVER) {
  providers.push(
    Nodemailer({
      server: process.env.EMAIL_SERVER,
      from: process.env.EMAIL_FROM,
    })
  );
}
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  providers.push(GitHub);
}
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  providers.push(Google);
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  ...(prisma && PrismaAdapter ? { adapter: PrismaAdapter(prisma) } : {}),
  trustHost: true,
  session: { strategy: "jwt" },
  providers,
  callbacks: {
    async session({ session, token }: any) {
      if (token.sub) (session.user as any).id = token.sub;
      if ((token as any).role) (session.user as any).role = (token as any).role;
      return session;
    },
    async jwt({ token, user }: any) {
      if (user) (token as any).role = (user as any).role || "user";
      if (token.sub && prisma) {
        try {
          const dbUser = await prisma.user.findUnique({
            where: { id: token.sub },
            select: { role: true },
          });
          if (dbUser) (token as any).role = dbUser.role;
        } catch {}
      }
      return token;
    },
  },
  pages: {
    signIn: "/auth/signin",
  },
});
