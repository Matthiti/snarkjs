import * as curves from "./curves.js";
import {utils} from "ffjavascript";
const {unstringifyBigInts} = utils;

export default async function saverVerifyEncryption(_saverPk, _ciphertext, logger) {
    const saverPk = unstringifyBigInts(_saverPk);
    const ciphertext = unstringifyBigInts(_ciphertext);

    const curve = await curves.getCurveFromName(saverPk.curve);

    const ct_c_0 = curve.G1.fromObject(ciphertext.c_0);
    const ct_c = ciphertext.c.map(c_i => curve.G1.fromObject(c_i));
    const ct_psi = curve.G1.fromObject(ciphertext.psi);
    const Z = saverPk.Z.map(Z_i => curve.G2.fromObject(Z_i));

    const validEncryption = await curve.pairingEq(
        ...Z.flatMap((Z_i, i) => [[ct_c_0, ...ct_c][i], Z_i]),
        curve.G1.neg(ct_psi), curve.G2.g
    );

    if (!validEncryption) {
        if (logger) logger.error("Invalid ciphertext");
        return false;
    }

    if (logger) logger.info("Valid ciphertext");
    return true;
}
