import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const target = req.nextUrl.searchParams.get("url");
  const res = await fetch(target!);
  return new NextResponse(await res.text());
}

export async function POST(req: NextRequest) {
  const body = await req.json();
  return NextResponse.redirect(body.next);
}
