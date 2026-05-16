import "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      cpf: string | null;
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
  }

  // Estende o User que vem do banco (usado no callback "session")
  interface User {
    cpf?: string | null;
  }
}