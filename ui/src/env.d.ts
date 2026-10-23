// Vite がビルド時に処理する CSS のサイドエフェクト import
declare module '*.css';
// Vite がビルド時に data: URI へ変換する画像
declare module '*.png' {
  const src: string;
  export default src;
}
// vite.config.ts の define が ui/package.json の version で置き換える
declare const __ZES_UI_VERSION__: string;
