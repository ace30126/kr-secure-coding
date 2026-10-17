import fs from "fs";
import { exec } from "child_process";

export default function handler(req: any, res: any) {
  const data = fs.readFileSync("./uploads/" + req.query.name);
  exec(`convert ./uploads/${req.query.name} out.png`);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.send(data);
}
