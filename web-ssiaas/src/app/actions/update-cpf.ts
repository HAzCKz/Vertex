"use server";

import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";
import { revalidatePath } from "next/cache";
import { isValidCpf } from "@/lib/validators/cpf";

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

  // Valida o CPF usando o algoritmo
  if (!cleanedCpf || !isValidCpf(cleanedCpf)) {
    return { success: false, error: "CPF inválido. Verifique os dígitos e tente novamente." };
  }

  // Atualiza o CPF do usuário no banco de dados
  try {
    await prisma.user.update({
      where: { id: session.user.id },
      data: { cpf: cleanedCpf },
    });
  } catch (error: unknown) {
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

  // Revalida a página para refletir a atualização do CPF
  revalidatePath("/completar-cadastro");

  return { success: true };
}