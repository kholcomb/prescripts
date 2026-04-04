#!/usr/bin/env node
import { buildProgram } from "./cli.js";

const program = buildProgram();
program.parse(process.argv);
