export interface ImageDimensions {
  height: number;
  type: string;
  width: number;
}

declare function imageSize(
  input: Uint8Array | string,
  callback?: (error: Error | null, dimensions?: ImageDimensions) => void,
): ImageDimensions | void;

declare namespace imageSize {
  const types: string[];
  function disableFS(disabled: boolean): void;
  function disableTypes(types: string[]): void;
  function setConcurrency(concurrency: number): void;
}

export = imageSize;
