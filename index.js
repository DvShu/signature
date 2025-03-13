import { hmacHash } from "ph-utils/crypto";
import { random } from "ph-utils";

/**
 * 将查询参数对象或 URLSearchParams 转换为查询字符串
 * @param {Object|URLSearchParams} query - 查询参数对象或 URLSearchParams 实例
 * @returns {string} 返回格式化后的查询字符串,以'?'开头,如果 query 为空则返回空字符串
 */
function queryStringify(query) {
  if (query) {
    let q;
    if (!(query instanceof URLSearchParams)) {
      q = new URLSearchParams(query);
    } else {
      q = query;
    }
    return `?${q.toString()}`;
  }
  return "";
}

/**
 * @typedef {Object} GenerateSignatureParam
 * @property {string} appid - 应用 ID
 * @property {secretKey} secretKey - 应用密钥
 * @property {string} url - 请求 URL
 * @property {string} [method="GET"] - 请求方法（可选，默认值为 GET）
 * @property {string|Object} [body=null] - 请求体（可选，默认值为 null）
 * @property {Object|URLSearchParams} [query=null] - 查询参数对象（可选，默认值为 null）
 * @property {boolean} [withHashName=true] - 是否包含签名算法名称（可选，默认值为 true）
 * @property {boolean} [pairValue=false] - true - 返回键值对值, false - 返回 `:` 分隔值
 */

/**
 * @typedef {Object} GenerateSignatureResult
 * @property {string} url - 完整的请求URL
 * @property {string} timestamp - 时间戳, 精确到秒
 * @property {string} nonce - 随机字符串
 * @property {string} rawSignatureStr - 原始签名字符串
 * @property {string} signature - 签名结果
 * @property {string} headerValue - 签名请求头值
 */

/**
 * 生成签名信息
 * @param {GenerateSignatureParam} options - 签名配置选项
 *
 * @example <caption>1. 生成签名</caption>
 * ```js
 * await generateSignature({ appid: "s", url: "/s", secretKey: "d" })
 * ```
 *
 * @example <caption>2. 生成不带算法名称的键值对值的签名</caption>
 * ```js
 * await generateSignature({ appid: "s", url: "/s", secretKey: "d", withHashName: false, pairValue: true })
 * ```
 *
 * @returns {Promise<GenerateSignatureResult>} 返回签名结果对象
 */
export async function generateSignature(options) {
  const opt = {
    method: "GET",
    pairValue: false,
    withHashName: true,
    ...options,
  };
  const m = opt.method.toUpperCase();
  const u = `${opt.url}${queryStringify(opt.query)}`;
  const signArr = [opt.appid, m, u];
  if (m !== "GET" && opt.body && opt.body !== "{}") {
    const b =
      typeof opt.body === "string" ? opt.body : JSON.stringify(opt.body);
    signArr.push(b);
  }
  const timestamp = `${Math.floor(Date.now() / 1000)}`;
  const nonce = random(8);
  signArr.push(timestamp, nonce, opt.secretKey);
  const signStr = `${signArr.join("&")}\n`;
  const signature = await hmacHash(signStr, opt.secretKey, "SHA-256", true);
  const headerPrefix = opt.withHashName ? "HMAC-SHA256 " : "";
  let headerValue = "";
  if (opt.pairValue) {
    headerValue = `appid=${opt.appid}&timestamp=${timestamp}&nonce=${nonce}&signature=${signature}`;
  } else {
    headerValue = `${opt.appid}:${timestamp}:${nonce}:${signature}`;
  }
  return {
    url: u,
    timestamp,
    nonce,
    rawSignatureStr: signStr,
    signature,
    headerValue: `${headerPrefix}${headerValue}`,
  };
}
