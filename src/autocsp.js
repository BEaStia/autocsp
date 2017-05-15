const _ = require('underscore')
const $ = require('zepto-browserify').$
const Base64 = require('crypto-js/enc-base64')
const fetch = require('whatwg-fetch')
const algorithms = {
  sha1: require('crypto-js/sha1'),
  sha256: require('crypto-js/sha256'),
  sha384: require('crypto-js/sha384'),
  sha512: require('crypto-js/sha512')
}

const urlRegexp = /(https?:)?\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/i
const domainRegexp = /(?!:\/\/)([a-zA-Z0-9]+\.)?[a-zA-Z0-9][a-zA-Z0-9-]+\.[a-zA-Z]{2,6}?/i

const AutoCSP = {
  algorithm: 'sha256',

  setup (algorithm) {
    if (!algorithms[algorithm]) {
      throw new Error('Not supported algorithm')
    }

    this.algorithm = algorithm
  },

  hash (data) {
    const algorithm = algorithms[this.algorithm]
    const hash = Base64.stringify(algorithm(data))
    return `${this.algorithm}-${hash}`
  },

  integrities () {
    const corsme = 'https://crossorigin.me/' // Thank you for your cors :*
    const defaults = {mode: 'cors', cache: 'default'}
    const scripts = $('script[src]').map((i, node) => $(node).attr('src'))

    const integrities = _.reject(scripts, this.isLocal).map((url) => {
      if (/^\/\//.test(url)) {
        url = `https:${url}`
      }

      const promise = fetch(`${corsme}${url}`, defaults)
        .then((response) => {
          return response.text()
        }).then((content) => {
          return { url: url, content: content }
        })

      return Promise.resolve(promise)
    })

    Promise
      .all(integrities)
      .then((resources) => {
        return _.map(resources, (resource) => {
          return {url: resource.url, hash: this.hash(resource.content)}
        })
      })
      .then((integrities) => {
        console.log('Integrity hashes from remote origin scripts:')
        console.table(integrities)
      })
  },

  hashes () {
    const inlines = $('script').filter(':not([src])').filter(':not([nonce])').map((i, node) => node.text)

    const hashes = _.map(inlines, (content) => {
      return {data: content, hash: this.hash(content)}
    })

    console.log('Nonce hashes for inline scripts:')
    console.table(hashes)
  },

  rule () {
    const scripts = $('script[src]').map((i, node) => $(node).attr('src'))
    const inlines = $('script').not('[src],[nonce]').map((i, node) => node.text)
    const nonces = $('script[nonce]').map((i, node) => $(node).attr('nonce'))
    const styles = $('link[rel="stylesheet"]').map((i, node) => $(node).attr('href'))
    const images = $('img[src]').map((i, node) => $(node).attr('src'))
    const frames = $('frame[src],iframe[src]').map((i, node) => $(node).attr('src'))
    const media = $('audio source,video source').map((i, node) => $(node).attr('src'))
    const objects = $('object,embed').map((i, node) => $(node).attr('data') || $(node).attr('src'))

    const fonts = ['/foo'] // FIXME
    const connects = ['/foo'] // FIXME

    const defaultSrc = " 'none'"
    const scriptSrc = this.getRemotes(scripts)
    const digestSrc = this.getHashes(inlines)
    const nonceSrc = this.getNonces(nonces)
    const styleSrc = this.getRemotes(styles)
    const imgSrc = this.getRemotes(images)
    const childSrc = this.getRemotes(frames)
    const mediaSrc = this.getRemotes(media)
    const objectSrc = this.getRemotes(objects)

    const fontSrc = this.getRemotes(fonts)
    const connectSrc = this.getRemotes(connects)

    return `Content-Security-Policy: default-src${defaultSrc}; script-src${scriptSrc}${digestSrc}${nonceSrc}; style-src${styleSrc}; img-src${imgSrc}; child-src${childSrc}; font-src${fontSrc}; connect-src${connectSrc}; media-src${mediaSrc}; object-src${objectSrc};`
  },

  isLocal (url) {
    return /^\/[^\/]/.test(url) || /^\./.test(url)
  },

  getRemotes (urls) {
    const self = _.some(urls, this.isLocal)

    const remotes = _.uniq(_.compact(_.map(urls, (url) => {
      const match = url.match(urlRegexp)
      const dmatch = match && match[0] && url.match(domainRegexp)

      return dmatch && dmatch[0]
    })))

    const rule = (self ? " 'self'" : '') + ['', ...remotes].join(' ')
    return (rule || " 'none'")
  },

  getNonces (values) {
    const nonces = _.map(values, (nonce) => {
      return `'nonce-${nonce}'`
    })

    return ['', ...nonces].join(' ')
  },

  getHashes (contents) {
    const hashes = _.map(contents, (content) => {
      return `'${this.hash(content)}'`
    })

    return ['', ...hashes].join(' ')
  }
}

module.exports = AutoCSP
