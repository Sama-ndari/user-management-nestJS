/* eslint-disable prettier/prettier */
import { randomUUID } from "crypto";
export const codeGenerate = () => {
  return randomUUID().slice(0, 6);
}