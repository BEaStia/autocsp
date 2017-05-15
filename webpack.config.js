const path = require('path')

module.exports = {
  context: path.join(__dirname, 'src'),
  entry: './autocsp',
  output: {
    path: path.join(__dirname, '/dist'),
    libraryTarget: 'var',
    filename: 'bundle.js',
    library: 'AutoCSP'
  },
  module: {
    loaders: [
      {test: /\.js$/, exclude: /node_modules/, loader: 'babel-loader'},
      {test: /\.json$/, loader: 'json-loader'}
    ]
  }
}
