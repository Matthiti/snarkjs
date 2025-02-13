import * as curves from "./curves.js";
import {utils} from "ffjavascript";
const {unstringifyBigInts} = utils;

export default async function saverEncrypt(_saverPk, _plaintexts, r) {
    const saverPk = unstringifyBigInts(_saverPk);
    const plaintexts = unstringifyBigInts(_plaintexts);

    if (saverPk.X.length !== plaintexts.length) {
        throw new Error("Plaintexts length doesn't correspond to public key");
    }

    const curve = await curves.getCurveFromName(saverPk.curve);
    const G1 = curve.G1;
    const Fr = curve.Fr;

    return {
        c_0: G1.toObject(G1.toAffine(
            G1.timesFr(G1.fromObject(saverPk.X_0), r)
        )),
        c: _plaintexts.map((s, i) =>
            G1.toObject(G1.toAffine(
                G1.add(
                    G1.timesFr(G1.fromObject(saverPk.X[i]), r),
                    G1.timesFr(G1.fromObject(saverPk.G_is[i]), Fr.e(s))
                )
            ))
        ),
        psi: G1.toObject(G1.toAffine(
            G1.add(
                G1.timesFr(G1.fromObject(saverPk.P_1), r),
                saverPk.Y.map((Y_i, i) => G1.timesFr(G1.fromObject(Y_i), Fr.e(plaintexts[i])))
                    .reduce((acc, cur) => G1.add(acc, cur))
            )
        ))
    };
}
