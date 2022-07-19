import {getCurveFromName} from "./curves.js";
import {utils} from "ffjavascript";
const {unstringifyBigInts} = utils;

export default async function saverDecrypt(_saverSk, _saverVk, _ciphertext) {
    const saverSk = unstringifyBigInts(_saverSk);
    const saverVk = unstringifyBigInts(_saverVk);
    const ciphertext = unstringifyBigInts(_ciphertext);

    const curve = await getCurveFromName(saverSk.curve);
    const G1 = curve.G1;
    const G2 = curve.G2;
    const Gt = curve.Gt;
    const Fr = curve.Fr;

    const ct_c_0 = G1.fromObject(ciphertext.c_0);
    const ct_c = ciphertext.c.map(c_i => G1.fromObject(c_i));
    const vk_V_n = saverVk.V_n.map(V_i => G2.fromObject(V_i));
    const vk_V_2n = saverVk.V_2n.map(V_2i => G2.fromObject(V_2i));
    const rho = Fr.fromObject(saverSk.rho);

    const m = await Promise.all(ct_c.map(async (c_i, i) => Gt.toObject(Gt.sub(
        await curve.pairing(c_i, vk_V_2n[i]),
        await curve.pairing(G1.timesFr(ct_c_0, rho), vk_V_n[i])
    ))));

    const nu = G1.toObject(G1.toAffine(G1.timesFr(ct_c_0, rho)));
    return { m, nu };
}
