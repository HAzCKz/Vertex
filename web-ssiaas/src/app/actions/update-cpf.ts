"use server";

import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";
import { revalidatePath } from "next/cache";

// Valida o formato do CPF (apenas estrutura, sem cálculo de dígitos)
function isValidCpfFormat(cpf: string): boolean {
  const cleaned = cpf.replace(/\D/g, "");
  return cleaned.length === 11;
}

type UpdateCpfResult =
  | { success: true }
  | { success: false; error: string };

export async function updateCpf(
  formData: FormData
): Promise<UpdateCpfResult> {
  // Garante que há uma sessão ativa e extrai o user ID
  const session = await auth();
  if (!session?.user?.id) {
    return { success: false, error: "Sessão inválida. Faça login novamente." };
  }

  // Extrai e limpa o CPF (remove pontos e traço)
  const rawCpf = formData.get("cpf") as string;
  const cleanedCpf = rawCpf?.replace(/\D/g, "");

  // Validação de formato do CPF
  if (!cleanedCpf || !isValidCpfFormat(cleanedCpf)) {
    return { success: false, error: "CPF inválido. Digite os 11 dígitos." };
  }

  // Atualiza o CPF do usuário no banco de dados
  try {
    await prisma.user.update({
      where: { id: session.user.id },
      data: { cpf: cleanedCpf },
    });
  } catch (error: unknown) {
    // Código P2002 é a violação de constraint unique do Prisma
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as { code: string }).code === "P2002"
    ) {
      return { success: false, error: "Este CPF já está cadastrado." };
    }
    return { success: false, error: "Erro ao salvar. Tente novamente." };
  }

  // Invalida o cache da sessão para o middleware ler o CPF atualizado
  revalidatePath("/completar-cadastro");

  return { success: true };
}