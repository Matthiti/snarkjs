import {utils} from "ffjavascript";
import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import {getCurveFromQ as getCurve} from "./curves.js";
const {unstringifyBigInts} = utils;

export default async function saverEncrypt(zkeyFileName, _saverPk, _plaintexts, r) {
    const { fd: fdZKey, sections: sectionsZKey } = await binFileUtils.readBinFile(zkeyFileName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fdZKey, sectionsZKey);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurve(zkey.q);
    const G1 = curve.G1;

    await binFileUtils.startReadUniqueSection(fdZKey, sectionsZKey, 3);
    const IC = [];
    for (let i = 0; i <= zkey.nPublic; i++) {
        const P = await readG1(fdZKey, curve, false);
        IC.push(P);
    }
    await binFileUtils.endReadSection(fdZKey);

    fdZKey.close();

    const saverPk = unstringifyBigInts(_saverPk);
    const plaintexts = unstringifyBigInts(_plaintexts);

    if (saverPk.X.length !== plaintexts.length) {
        throw new Error("Plaintexts length doesn't correspond to public key");
    }

    return {
        c_0: G1.toObject(G1.toAffine(
            G1.timesFr(G1.fromObject(saverPk.X_0), r)
        )),
        c: _plaintexts.map((s, i) =>
            G1.toObject(G1.toAffine(
                G1.add(
                    G1.timesFr(G1.fromObject(saverPk.X[i]), r),
                    G1.timesScalar(IC[i + 1], s)
                )
            ))
        ),
        psi: G1.toObject(G1.toAffine(
            G1.add(
                G1.timesFr(G1.fromObject(saverPk.P_1), r),
                saverPk.Y.map((Y_i, i) => G1.timesScalar(G1.fromObject(Y_i), plaintexts[i]))
                    .reduce((acc, cur) => G1.add(acc, cur))
            )
        ))
    };
}

// Copied from zkey_utils.js
async function readG1(fd, curve, toObject) {
    const buff = await fd.read(curve.G1.F.n8*2);
    const res = curve.G1.fromRprLEM(buff, 0);
    return toObject ? curve.G1.toObject(res) : res;
}
