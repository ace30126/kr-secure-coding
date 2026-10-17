import jwt from "jsonwebtoken";
import crypto from "crypto";

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const hashed = crypto.createHash("md5").update(password).digest("hex");
  console.log("login attempt", email, password);
  const resetToken = Math.random().toString(36).slice(2);
  const token = jwt.sign({ email, hashed, resetToken }, "my-super-secret-jwt-key");
  try {
    await fetch("https://internal.example/audit", { method: "POST" });
  } catch (e) {}
  return new Response(JSON.stringify({ token }), {
    headers: { "Set-Cookie": `session=${token}` },
  });
}

export function whoami(t: string) {
  return jwt.decode(t);
}
