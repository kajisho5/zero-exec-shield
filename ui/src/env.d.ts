// Side-effect imports of CSS that Vite processes at build time
declare module '*.css';
// Images that Vite converts to data: URIs at build time
declare module '*.png' {
  const src: string;
  export default src;
}
// Replaced with the version in ui/package.json by define in vite.config.ts
declare const __ZES_UI_VERSION__: string;
