// webpack.mix.js

let mix = require('laravel-mix');

mix.disableSuccessNotifications();

// Compile
mix.js('src/js/main.js', 'js')
.sass('src/scss/bootstrap.scss', 'css')
.setPublicPath('public/assets');

// Copy bootstrap-icons module
mix.copy('node_modules/bootstrap-icons/font/', 'public/assets/fonts/bootstrap-icons');