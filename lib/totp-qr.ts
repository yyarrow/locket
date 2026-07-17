import jsQR from "jsqr";

const MAX_FILE_BYTES = 15 * 1024 * 1024;
const MAX_IMAGE_DIMENSION = 2600;

function loadImage(url: string) {
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.decoding = "async";
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("无法读取这张图片"));
    image.src = url;
  });
}

export async function decodeTotpQrImage(file: Blob) {
  if (file.size > MAX_FILE_BYTES) throw new Error("二维码图片不能超过 15 MB");
  if (file.type && !file.type.startsWith("image/")) throw new Error("请选择二维码图片或截图");

  const objectUrl = URL.createObjectURL(file);
  try {
    const image = await loadImage(objectUrl);
    if (!image.naturalWidth || !image.naturalHeight) throw new Error("图片尺寸无效");

    const scale = Math.min(1, MAX_IMAGE_DIMENSION / Math.max(image.naturalWidth, image.naturalHeight));
    const width = Math.max(1, Math.round(image.naturalWidth * scale));
    const height = Math.max(1, Math.round(image.naturalHeight * scale));
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("当前浏览器无法解析二维码");
    context.drawImage(image, 0, 0, width, height);

    const pixels = context.getImageData(0, 0, width, height);
    const result = jsQR(pixels.data, width, height, { inversionAttempts: "attemptBoth" });
    if (!result?.data) throw new Error("图片中没有识别到二维码");
    if (!result.data.trim().toLowerCase().startsWith("otpauth://totp/")) {
      throw new Error("这个二维码不是 TOTP 动态验证码");
    }
    return result.data.trim();
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
