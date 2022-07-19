import * as curves from "./curves.js";
import {Scalar, utils} from "ffjavascript";
import saverVerifyEncryption from "./saver_verify_encryption.js";
const {unstringifyBigInts} = utils;

export default async function saverVerifyEncryptionAndProof(_vk_verifier, _saverPk, _ciphertext, _publicSignals, _proof, logger) {
    const vk_verifier = unstringifyBigInts(_vk_verifier);
    const saverPk = unstringifyBigInts(_saverPk);
    const ciphertext = unstringifyBigInts(_ciphertext);
    const publicSignals = unstringifyBigInts(_publicSignals);
    const proof = unstringifyBigInts(_proof);

    const curve = await curves.getCurveFromName(vk_verifier.curve);

    const ct_c_0 = curve.G1.fromObject(ciphertext.c_0);
    const ct_c = ciphertext.c.map(c_i => curve.G1.fromObject(c_i));

    const validEncryption = await saverVerifyEncryption(saverPk, ciphertext, logger);

    if (!validEncryption) {
        return false;
    }

    const IC0 = curve.G1.fromObject(vk_verifier.IC[0]);
    const IC = new Uint8Array(curve.G1.F.n8*2 * publicSignals.length);
    const w = new Uint8Array(curve.Fr.n8 * publicSignals.length);

    for (let i = 0; i < publicSignals.length; i++) {
        const buffP = curve.G1.fromObject(vk_verifier.IC[i + ciphertext.c.length + 1]);
        IC.set(buffP, i * curve.G1.F.n8*2);
        Scalar.toRprLE(w, curve.Fr.n8 * i, publicSignals[i], curve.Fr.n8);
    }

    let cpub = await curve.G1.multiExpAffine(IC, w);
    cpub = curve.G1.add(cpub, IC0);

    // Add ciphertext
    cpub = curve.G1.add(cpub,
        ct_c.reduce((acc, cur) => curve.G1.add(acc, cur), ct_c_0)
    );

    const pi_a = curve.G1.fromObject(proof.pi_a);
    const pi_b = curve.G2.fromObject(proof.pi_b);
    const pi_c = curve.G1.fromObject(proof.pi_c);

    const vk_gamma_2 = curve.G2.fromObject(vk_verifier.vk_gamma_2);
    const vk_delta_2 = curve.G2.fromObject(vk_verifier.vk_delta_2);
    const vk_alpha_1 = curve.G1.fromObject(vk_verifier.vk_alpha_1);
    const vk_beta_2 = curve.G2.fromObject(vk_verifier.vk_beta_2);

    const res = await curve.pairingEq(
        curve.G1.neg(pi_a) , pi_b,
        cpub , vk_gamma_2,
        pi_c , vk_delta_2,

        vk_alpha_1, vk_beta_2
    );

    if (! res) {
        if (logger) logger.error("Invalid proof");
        return false;
    }

    if (logger) logger.info("OK!");
    return true;

}
