/**
 * 签名配置选项
 */
export interface GenerateSignatureParam {
  /** 应用 ID */
  appid: string;
  /** 应用密钥 */
  secretKey: string;
  /** 请求 URL */
  url: string;
  /** 请求方法（可选，默认值为 GET） */
  method?: string;
  /** 请求体（可选，默认值为 null） */
  body?: string | Record<string, any>;
  /** 查询参数对象（可选，默认值为 null） */
  query?: Record<string, any> | URLSearchParams;
  /** 是否包含签名算法名称（可选，默认值为 true） */
  withHashName?: boolean;
  /** true - 返回键值对值, false - 返回 `:` 分隔值 */
  pairValue?: boolean;
}

/**
 * 签名结果对象
 */
export interface GenerateSignatureResult {
  /** 完整的请求URL */
  url: string;
  /** 时间戳, 精确到秒 */
  timestamp: string;
  /** 随机字符串 */
  nonce: string;
  /** 原始签名字符串 */
  rawSignatureStr: string;
  /** 签名结果 */
  signature: string;
  /** 签名请求头值 */
  headerValue: string;
}

/**
 * 生成签名信息
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
 * @param {GenerateSignatureParam} options - 签名配置选项
 * @returns {Promise<GenerateSignatureResult>} 返回签名结果对象
 */
export function generateSignature(
  options: GenerateSignatureParam
): Promise<GenerateSignatureResult>;
