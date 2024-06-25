import { BigNumberish } from "ethers";
import { ethers } from "hardhat";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { expect } = require("chai");

describe("evm-verifier", function () {
  it("Verify a ring signature", async function () {
    // link libraries
    const contractFactory = await ethers.getContractFactory("RingSigVerifier");

    // deploy SigVerifier contract
    const SigVerifier = await contractFactory.deploy();

    const message =
      40340039748299835169756547746037309976814975367605249759025889748097184499642n;

    const ring_: BigNumberish[] = [
      10332262407579932743619774205115914274069865521774281655691935407979316086911n,
      100548694955223641708987702795059132275163693243234524297947705729826773642827n,
      15164162595175125008547705889856181828932143716710538299042410382956573856362n,
      20165396248642806335661137158563863822683438728408180285542980607824890485122n,
      30103554500144535254965021336757008479704861502777924021458799636567575289359n,
      52090609727678693574435399254703833889410700116234244177206170117175907888773n,
    ];

    const responses: BigNumberish[] = [
      11804634253715958305924663675149570036087556552259958445438461057755571312556n,
      54504904582581664190079678841661949924646048914257204184447875552904565842816n,
      39029979142995495559808722560230252062143262593772751292415635904439923318057n,
    ];

    const c: BigNumberish =
      63894040806659059839317990719410380194290503251271615962483579211495165605502n;

    console.log("ringSize: ", ring_.length / 2);
    console.log("responses len: ", responses.length);
    console.log(
      "output: ",
      await SigVerifier.verifyRingSignature(message, ring_, responses, c),
    );
    expect(
      await SigVerifier.verifyRingSignature(message, ring_, responses, c),
    ).to.equal(true);
  });
});
