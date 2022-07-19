import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import {getCurveFromQ as getCurve} from "./curves.js";
import * as misc from "./misc.js";

export default async function saverKeygen(zkeyName, n, entropy, logger) {
    const { fd, sections } = await binFileUtils.readBinFile(zkeyName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fd, sections);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurve(zkey.q);
    const Fr = curve.Fr;
    const G1 = curve.G1;
    const G2 = curve.G2;

    await binFileUtils.startReadUniqueSection(fd, sections, 3);
    const IC = [];
    for (let i = 0; i <= zkey.nPublic; i++) {
        const P = await readG1(fd, curve, false);
        IC.push(P);
    }
    await binFileUtils.endReadSection(fd);

    if (logger) logger.info("Generating randomness");
    const rng = await misc.getRandomRng(entropy);
    const s = [...Array(n)].map(() => Fr.fromRng(rng));
    const v = [...Array(n)].map(() => Fr.fromRng(rng));
    const t_0 = Fr.fromRng(rng);
    const t = [...Array(n)].map(() => Fr.fromRng(rng));
    const rho = Fr.fromRng(rng);

    if (logger) logger.info("Constructing key");

    const pk = {
        X_0: G1.toObject(zkey.vk_delta_1),
        X:   s.map(s_i => G1.toObject(G1.toAffine(G1.timesFr(zkey.vk_delta_1, s_i)))),
        Y:   t.map((t_i, i) => G1.toObject(G1.toAffine(G1.timesFr(IC[i + 1], t_i)))),
        Z:   [t_0, ...t].map(t_i => G2.toObject(G2.toAffine(G2.timesFr(G2.g, t_i)))),
        P_1: G1.toObject(G1.toAffine(G1.timesFr(
            zkey.vk_delta_1,
            Fr.add(
                t_0,
                t.map((t_i, i) => Fr.mul(t_i, s[i]))
                    .reduce((acc, cur) => Fr.add(acc, cur))
            )
        ))),
        P_2: G1.toObject(G1.toAffine(G1.timesFr(
            zkey.vk_neg_gamma_1,
            s.reduce((acc, cur) => Fr.add(acc, cur), Fr.one)
        ))),
        G_is: IC.slice(1, n + 1).map(G_i => G1.toObject(G1.toAffine(G_i))),
        curve: curve.name
    };

    const sk = {
        rho: Fr.toObject(rho),
        curve: curve.name
    };

    const vk = {
        V_0:  G2.toObject(G2.toAffine(G2.timesFr(G2.g, rho))),
        V_n:  s.map((s_i, i) => G2.toObject(G2.toAffine(G2.timesFr(G2.g, Fr.mul(s_i, v[i]))))),
        V_2n: v.map(v_i => G2.toObject(G2.toAffine(G2.timesFr(G2.g, Fr.mul(rho, v_i))))),
        curve: curve.name
    };

    await fd.close();

    return { pk, sk, vk };
}

// Copied from zkey_utils.js
async function readG1(fd, curve, toObject) {
    const buff = await fd.read(curve.G1.F.n8*2);
    const res = curve.G1.fromRprLEM(buff, 0);
    return toObject ? curve.G1.toObject(res) : res;
}
