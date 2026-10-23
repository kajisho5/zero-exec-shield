// Vite がビルド時に処理する CSS のサイドエフェクト import
declare module '*.css';
// Vite がビルド時に data: URI へ変換する画像
declare module '*.png' {
  const src: string;
  export default src;
}
