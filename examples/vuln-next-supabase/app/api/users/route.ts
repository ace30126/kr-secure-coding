import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

// 인증 확인 없이 사용자 삭제
export async function DELETE(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id");
  await db.query(`DELETE FROM users WHERE id = ${id}`);
  return NextResponse.json({ ok: true });
}

export async function GET(req: NextRequest) {
  try {
    const name = req.nextUrl.searchParams.get("name");
    const rows = await db.query("SELECT * FROM users WHERE name = '" + name + "'");
    return NextResponse.json(rows);
  } catch (e: any) {
    return NextResponse.json({ error: e.stack }, { status: 500 });
  }
}
