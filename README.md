# Signature

使用 `JS` 封装的一套前后端通用的签名工具，包含：生成签名、验签

## 使用

### 1. 安装

```bash
npm install @asteres/signature
```

### 2. 引入

```js
import {
  generateSignature,
  verifySignature,
  generateSignatureHeader,
  verifySignatureHeader,
} from "@asteres/signature";
```

### 3. 使用

```js
const res = await generateSignature(...);
const res = await verifySignature(...);
```

## API

### 生成签名

1. `generateSignature(): Promise<Result>` 生成签名

2. `generateSignatureHeader(): Promise<Result>` 生成签名并组装为请求头参数

### 验证签名

1. `verifySignature(): Promise<Result>` 验证签名
2. `verifySignatureHeader(): Promise<Result>` 验证签名头参数
