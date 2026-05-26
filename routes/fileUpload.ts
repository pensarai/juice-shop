/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

const MAX_ENTITY_EXPANSION_SIZE = 1048576 // 1MB maximum total entity expansion

function hasExcessiveEntityExpansion (data: string): boolean {
  const internalEntityPattern = /<!ENTITY\s+(\w+)\s+(?:"([^"]*)"|'([^']*)')\s*>/g

  const entities: Map<string, string> = new Map()
  let match

  while ((match = internalEntityPattern.exec(data)) !== null) {
    entities.set(match[1], match[2] || match[3])
  }

  if (entities.size === 0) return false

  // Compute the expanded size of each entity and the max nesting depth
  const expandedSizes: Map<string, number> = new Map()
  const nestingDepths: Map<string, number> = new Map()

  function getExpandedSize (entityName: string, visited: Set<string>): number {
    if (expandedSizes.has(entityName)) return expandedSizes.get(entityName)!
    if (!entities.has(entityName) || visited.has(entityName)) return 0
    visited.add(entityName)

    const value = entities.get(entityName)!
    let size = value.length
    let refMatch
    const refRegex = /&(\w+);/g
    while ((refMatch = refRegex.exec(value)) !== null) {
      const refName = refMatch[1]
      if (entities.has(refName)) {
        size += getExpandedSize(refName, new Set(visited)) - refMatch[0].length
      }
    }
    expandedSizes.set(entityName, size)
    return size
  }

  function getNestingDepth (entityName: string, visited: Set<string>): number {
    if (nestingDepths.has(entityName)) return nestingDepths.get(entityName)!
    if (!entities.has(entityName) || visited.has(entityName)) return 0
    visited.add(entityName)

    const value = entities.get(entityName)!
    let maxChildDepth = 0
    let refMatch
    const refRegex = /&(\w+);/g
    while ((refMatch = refRegex.exec(value)) !== null) {
      const refName = refMatch[1]
      if (entities.has(refName)) {
        const childDepth = getNestingDepth(refName, new Set(visited))
        maxChildDepth = Math.max(maxChildDepth, childDepth + 1)
      }
    }
    nestingDepths.set(entityName, maxChildDepth)
    return maxChildDepth
  }

  // Compute nesting depths for all entities
  let maxDepth = 0
  for (const name of entities.keys()) {
    const depth = getNestingDepth(name, new Set())
    maxDepth = Math.max(maxDepth, depth)
  }

  // If nesting depth >= 3, libxml2's entity loop detection will handle it safely
  if (maxDepth >= 3) return false

  // For shallow nesting (depth <= 2), compute total expansion from document body and entity values
  let totalExpansion = 0

  // Count entity references in the document body (outside DTD)
  const dtdEnd = data.indexOf(']>')
  const bodyContent = dtdEnd !== -1 ? data.substring(dtdEnd + 2) : data

  let bodyRefMatch
  const bodyRefRegex = /&(\w+);/g
  while ((bodyRefMatch = bodyRefRegex.exec(bodyContent)) !== null) {
    const refName = bodyRefMatch[1]
    if (entities.has(refName)) {
      totalExpansion += getExpandedSize(refName, new Set())
    }
  }

  return totalExpansion > MAX_ENTITY_EXPANSION_SIZE
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      if (hasExcessiveEntityExpansion(data)) {
        if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
          challengeUtils.solve(challenges.xxeDosChallenge)
        }
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        return
      }
      try {
        const sandbox = { libxml, data }
        vm.createContext(sandbox)
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
        const xmlString = xmlDoc.toString(false)
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

const MAX_YAML_ALIASES = 50

function hasExcessiveAliases (data: string): boolean {
  const aliasMatches = data.match(/\*\w/g)
  return aliasMatches != null && aliasMatches.length > MAX_YAML_ALIASES
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      if (hasExcessiveAliases(data)) {
        if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
          challengeUtils.solve(challenges.yamlBombChallenge)
        }
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        return
      }
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Invalid string length') || utils.contains(errorMessage, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
