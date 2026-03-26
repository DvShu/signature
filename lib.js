import { HmacSHA256 } from "crypto-es";

const b = HmacSHA256("message", "secret").toString();
console.log(b);