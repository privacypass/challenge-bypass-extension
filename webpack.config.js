import CopyWebpackPlugin from 'copy-webpack-plugin';
import HtmlWebpackPlugin from 'html-webpack-plugin';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';
import TsconfigPathsPlugin from 'tsconfig-paths-webpack-plugin';
import path from 'path';

// import buffer from "buffer";
// import streamBrowserify from "stream-browserify";

const __dirname = (() => {
  const filepath_uri = import.meta.url;
  const prefix = `file:${path.sep === '/' ? '' : path.sep}`;
  let fp;
  fp = path.normalize(filepath_uri);
  fp = (fp.indexOf(prefix) === 0) ? fp.substring(prefix.length, fp.length) : new URL(filepath_uri).pathname;
  fp = path.dirname(fp);
  return fp;
})();

const tsloader = {
    test: /\.tsx?$/,
    exclude: /node_modules/,
    loader: 'ts-loader',
    options: {
        projectReferences: true,
    },
};

const common = {
    output: {
        path: path.resolve('PrivacyPass'),
    },
    context: __dirname,
    mode: 'production',
    optimization: {
        minimize: false,
    },
};

const background = {
    ...common,
    entry: {
        background: path.resolve('src/background/index.ts'),
    },
    externals: { crypto: 'null' },
    module: {
        rules: [tsloader],
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
        fallback: {
            // 'buffer': buffer,
            // 'stream': streamBrowserify,
        },
    },
};

const popup = {
    ...common,
    entry: {
        popup: path.resolve('src/popup/index.tsx'),
    },
    module: {
        rules: [
            tsloader,
            {
                test: /\.scss?$/,
                use: [MiniCssExtractPlugin.loader, 'css-loader', 'sass-loader'],
            },
            { test: /\.(png|jpe?g|gif|svg)$/, use: 'file-loader' },
        ],
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js', '.scss', '.json', '.svg', '.html'],
        plugins: [
            new TsconfigPathsPlugin({
                extensions: ['.tsx', '.ts', '.js', '.scss', '.json', '.svg', '.html'],
                configFile: 'src/popup/tsconfig.json',
            }),
        ],
    },
    plugins: [
        new CopyWebpackPlugin({
            patterns: [{ from: 'public/icons', to: 'icons' }, { from: 'public/manifest.json' }],
        }),
        new HtmlWebpackPlugin({
            chunks: ['popup'],
            filename: 'popup.html',
            template: 'public/popup.html',
        }),
        new MiniCssExtractPlugin(),
    ],
};

// Mutiple targets for webpack: https://webpack.js.org/concepts/targets/#multiple-targets
export default [background, popup];
