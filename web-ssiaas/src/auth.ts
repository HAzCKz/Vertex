import NextAuth from "next-auth";
import Google from "next-auth/providers/google";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { prisma } from "@/lib/prisma";

export const { handlers, auth, signIn, signOut } = NextAuth({
  // O adapter conecta o Auth.js ao banco via Prisma.
  // Ele gerencia automaticamente as tabelas Account, Session e User.
  adapter: PrismaAdapter(prisma),

  providers: [
    Google({
      clientId: process.env.AUTH_GOOGLE_ID!,
      clientSecret: process.env.AUTH_GOOGLE_SECRET!,
    }),
  ],

  // Usamos a estratégia "database" — a sessão fica salva no PostgreSQL.
  // A alternativa seria "jwt" (token no cookie), mas database é mais
  // segura para uma plataforma SSI onde precisamos de controle total.
  session: {
    strategy: "database",
  },

  callbacks: {
    // O callback "session" é chamado toda vez que alguém checa a sessão.
    // Por padrão, o Auth.js só expõe name/email/image.
    // Aqui foi adicionado o "id" e o "cpf" do banco ao objeto de sessão,
    // pois o middleware vai precisar checar se o CPF existe.
    async session({ session, user }) {
      session.user.id = user.id;
      session.user.cpf = (user as { cpf?: string | null }).cpf ?? null;
      return session;
    },
  },

  pages: {
    signIn: '/login', 
  }
});