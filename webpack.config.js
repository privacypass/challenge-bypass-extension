import CopyWebpackPlugin from 'copy-webpack-plugin';
import HtmlWebpackPlugin from 'html-webpack-plugin';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';
import path from 'path';

// import buffer from "buffer";
// import streamBrowserify from "stream-browserify";

const __dirname = path.dirname(new URL(import.meta.url).pathname);

export default {
    entry: {
        popup: path.resolve('src/popup/index.tsx'),
        background: path.resolve('src/background/index.ts'),
    },
    output: {
        path: path.resolve('dist'),
    },
    context: __dirname,
    mode: 'production',
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                exclude: /node_modules/,
                loader: 'ts-loader',
                options: {
                    transpileOnly: true,
                    projectReferences: true,
                },
            },
            { test: /\.scss?$/, use: [MiniCssExtractPlugin.loader, 'css-loader', 'sass-loader'] },
            { test: /\.(png|jpe?g|gif|svg)$/, use: 'file-loader' },
        ],
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
        fallback: {
            // 'buffer': buffer,
            // 'stream': streamBrowserify,
        },
        alias: {
            '@root': path.resolve(__dirname),
            '@public': path.resolve(__dirname, 'public'),
            '@popup': path.resolve(__dirname, 'src/popup'),
        },
    },
    externals: { crypto: 'null' },
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
    optimization: {
        minimize: false,
    },
};
