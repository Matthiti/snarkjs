import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import * as wtnsUtils from "./wtns_utils.js";
import {getCurveFromQ as getCurve} from "./curves.js";
import {Scalar, utils} from "ffjavascript";
import wtns_calculate from "./wtns_calculate.js";
import groth16Prove from "./groth16_prove.js";
import saverEncrypt from "./saver_encrypt.js";

const {stringifyBigInts, unstringifyBigInts} = utils;

// Encrypts the first n public inputs
export default async function saverEncryptThenProve(_input, wasmFile, zkeyFileName, _saverPk, logger) {
    const { fd: fdZKey, sections: sectionsZKey } = await binFileUtils.readBinFile(zkeyFileName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fdZKey, sectionsZKey);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurve(zkey.q);
    const Fr = curve.Fr;
    const G1 = curve.G1;

    /*
        Start witness calculation
    */
    const input = unstringifyBigInts(_input);
    const wtnsObject = {
        type: "mem"
    };
    await wtns_calculate(input, wasmFile, wtnsObject);

    const { fd: fdWtns, sections: sectionsWtns } = await binFileUtils.readBinFile(wtnsObject, "wtns", 2, 1<<25, 1<<23);
    const wtns = await wtnsUtils.readHeader(fdWtns, sectionsWtns);

    if (!Scalar.eq(zkey.r,  wtns.q)) {
        throw new Error("Curve of the witness does not match the curve of the proving key");
    }

    if (wtns.nWitness != zkey.nVars) {
        throw new Error(`Invalid witness length. Circuit: ${zkey.nVars}, witness: ${wtns.nWitness}`);
    }

    if (logger) logger.debug("Reading Wtns");
    const buffWitness = await binFileUtils.readSection(fdWtns, sectionsWtns, 2);

    const saverPk = unstringifyBigInts(_saverPk);

    // TODO: for now, we encrypt the first n public inputs (including public outputs first)
    const encryptedSignals = [];
    for (let i = 1; i <= saverPk.X.length; i++) {
        const b = buffWitness.slice(i*Fr.n8, i*Fr.n8+Fr.n8);
        encryptedSignals.push(Scalar.fromRprLE(b));
    }

    /*
        Create ciphertext
    */
    const r = Fr.random();
    const ciphertext = await saverEncrypt(saverPk, encryptedSignals, r);

    await fdZKey.close();
    await fdWtns.close();

    const { proof, publicSignals } = await groth16Prove(zkeyFileName, wtnsObject, logger);
    proof.pi_c = stringifyBigInts(G1.toObject(G1.toAffine(
        G1.add(
            G1.fromObject(unstringifyBigInts(proof.pi_c)),
            G1.timesFr(
                G1.fromObject(saverPk.P_2),
                r
            )
        )
    )));

    return { proof, publicSignals: publicSignals.slice(encryptedSignals.length), ciphertext };
}
