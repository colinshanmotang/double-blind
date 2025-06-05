import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import nodePolyfills from 'rollup-plugin-node-polyfills';

export default {
  input: 'groupSignatures.js',
  output: {
    file: 'dist/bundle.js',
    format: 'iife', // Change to IIFE format
    name: 'bundle', // Add a name for the IIFE
    globals: {
      module: 'module'
    }
  },
  plugins: [
    nodePolyfills(),
    resolve({
      browser: true,
      preferBuiltins: false
    }),
    commonjs({
      transformMixedEsModules: true,
      requireReturnsDefault: 'auto',
      include: /node_modules/,
      strictRequires: true
    }),
    json()
  ],
  external: []
};