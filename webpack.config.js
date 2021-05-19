const path = require('path');
const CopyWebpackPlugin = require("copy-webpack-plugin");
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
    entry: {
        popup:'./src/popup/index.tsx',
        background: './src/background/index.ts',
    },
    mode: 'production',
    module: {
        rules: [
            { test: /\.tsx?$/, use: 'ts-loader', exclude: /node_modules/ },
            { test: /\.scss?$/, use: [MiniCssExtractPlugin.loader, 'css-loader', 'sass-loader'] },
        ],
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
        alias: {
            '@root': path.resolve(__dirname),
            '@public': path.resolve(__dirname, 'public'),
            '@background': path.resolve(__dirname, 'src/background'),
            '@popup': path.resolve(__dirname, 'src/popup'),
        },
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
    },
    plugins: [
        new CopyWebpackPlugin({
            patterns: [
                { from: 'public/icons', to: 'icons' },
                { from: 'public/manifest.json' },
            ],
        }),
        new HtmlWebpackPlugin({
            chunks: ['popup'],
            filename: 'popup.html',
            template: 'public/popup.html',
        }),
        new MiniCssExtractPlugin(),
    ],
};
