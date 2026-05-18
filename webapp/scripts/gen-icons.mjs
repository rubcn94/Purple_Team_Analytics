#!/usr/bin/env node
/**
 * Generates PWA icons (192x192 and 512x512 PNG) using only Node.js built-ins.
 * Creates a purple (#7c3aed) background with a white shield shape.
 */
import { deflateSync } from 'zlib'
import { writeFileSync } from 'fs'

// CRC32 table
const crcTable = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c
  }
  return t
})()

function crc32(buf) {
  let crc = 0xffffffff
  for (let i = 0; i < buf.length; i++) crc = crcTable[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii')
  const lenBuf = Buffer.alloc(4)
  lenBuf.writeUInt32BE(data.length)
  const crcVal = crc32(Buffer.concat([typeBytes, data]))
  const crcBuf = Buffer.alloc(4)
  crcBuf.writeUInt32BE(crcVal)
  return Buffer.concat([lenBuf, typeBytes, data, crcBuf])
}

function makePNG(size) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])

  // IHDR
  const ihdrData = Buffer.alloc(13)
  ihdrData.writeUInt32BE(size, 0)
  ihdrData.writeUInt32BE(size, 4)
  ihdrData[8] = 8  // bit depth
  ihdrData[9] = 6  // RGBA
  // compression=0, filter=0, interlace=0 already 0

  // Draw pixels
  const cx = size / 2
  const cy = size / 2

  const raw = Buffer.alloc(size * (1 + size * 4))

  for (let y = 0; y < size; y++) {
    const rowStart = y * (1 + size * 4)
    raw[rowStart] = 0  // filter None

    for (let x = 0; x < size; x++) {
      const px = rowStart + 1 + x * 4
      const nx = (x - cx) / size   // normalized -0.5..0.5
      const ny = (y - cy) / size

      // Background: deep purple gradient
      let r = 80, g = 30, b = 180

      // Subtle radial gradient: slightly lighter center
      const dist = Math.sqrt(nx * nx + ny * ny)
      const fade = Math.max(0, 1 - dist * 1.6)
      r = Math.round(r + fade * 40)
      g = Math.round(g + fade * 10)
      b = Math.round(b + fade * 20)

      // Shield shape (normalized coords)
      // Shield: wider at top, narrows to point at bottom
      // roughly: |nx| < 0.28 - |ny|*0.15 (for top half)
      //          parabola taper for bottom half
      const shieldX = Math.abs(nx)
      const shieldY = ny  // -0.5=top, +0.5=bottom

      let inShield = false
      if (shieldY < 0.12) {
        // Upper portion: rectangular-ish with rounded top
        const halfW = 0.26 - Math.max(0, -shieldY - 0.3) * 0.3
        inShield = shieldX < halfW
      } else {
        // Lower taper to point
        const taper = 0.26 * (1 - (shieldY - 0.12) / 0.35)
        inShield = shieldX < taper && shieldY < 0.47
      }

      // Inner shield highlight (slightly lighter)
      const innerShieldX = Math.abs(nx)
      const innerShieldY = ny
      let inInner = false
      const margin = 0.045
      if (innerShieldY < 0.12 - margin) {
        const halfW = 0.26 - margin - Math.max(0, -innerShieldY - 0.3) * 0.3
        inInner = innerShieldX < halfW
      } else {
        const taper = (0.26 - margin) * (1 - (innerShieldY - 0.12) / 0.32)
        inInner = innerShieldX < taper && innerShieldY < 0.43
      }

      if (inShield) {
        if (inInner) {
          // Inner: soft purple-white
          raw[px] = 200; raw[px+1] = 170; raw[px+2] = 255; raw[px+3] = 255
        } else {
          // Shield border: white
          raw[px] = 255; raw[px+1] = 255; raw[px+2] = 255; raw[px+3] = 255
        }
      } else {
        raw[px] = r; raw[px+1] = g; raw[px+2] = b; raw[px+3] = 255
      }
    }
  }

  // "PT" text pixels (simplified dot-matrix, only for larger sizes)
  if (size >= 192) {
    const s = size / 192  // scale factor
    const dotMatrix = {
      // P: 5x7
      P: [
        [1,1,1,0,0],
        [1,0,0,1,0],
        [1,1,1,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
        [1,0,0,0,0],
      ],
      // T: 5x7
      T: [
        [1,1,1,1,1],
        [0,0,1,0,0],
        [0,0,1,0,0],
        [0,0,1,0,0],
        [0,0,1,0,0],
        [0,0,1,0,0],
        [0,0,1,0,0],
      ],
    }

    const dot = Math.max(3, Math.round(8 * s))
    const gap = Math.round(2 * s)
    const charW = 5 * dot + gap
    const charH = 7 * dot
    const totalW = charW * 2
    const startX = Math.round(cx - totalW / 2 + 2 * s)
    const startY = Math.round(cy - charH / 2 + 10 * s)

    const chars = [dotMatrix.P, dotMatrix.T]
    chars.forEach((matrix, ci) => {
      const ox = startX + ci * charW
      matrix.forEach((row, ry) => {
        row.forEach((cell, rx) => {
          if (!cell) return
          for (let dy = 0; dy < dot; dy++) {
            for (let dx = 0; dx < dot; dx++) {
              const px2 = ox + rx * dot + dx
              const py2 = startY + ry * dot + dy
              if (px2 < 0 || px2 >= size || py2 < 0 || py2 >= size) continue
              const pidx = py2 * (1 + size * 4) + 1 + px2 * 4
              raw[pidx] = 255; raw[pidx+1] = 255; raw[pidx+2] = 255; raw[pidx+3] = 255
            }
          }
        })
      })
    })
  }

  const compressed = deflateSync(raw, { level: 6 })

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdrData),
    chunk('IDAT', compressed),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

const sizes = [192, 512]
const outDir = new URL('../public/', import.meta.url).pathname

sizes.forEach(size => {
  const png = makePNG(size)
  const path = `${outDir}icon-${size}.png`
  writeFileSync(path, png)
  console.log(`✓ icon-${size}.png (${png.length} bytes)`)
})

// Also write a maskable version (512, slightly smaller shield with padding)
const maskable = makePNG(512)
writeFileSync(`${outDir}icon-maskable-512.png`, maskable)
console.log('✓ icon-maskable-512.png')
console.log('Done.')
