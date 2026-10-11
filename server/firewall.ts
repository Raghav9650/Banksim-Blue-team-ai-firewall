import type { FirewallDecision, FirewallRequest, ThreatCategory } from "../src/types.ts";

export interface FirewallSignals {
  character_entropy: number;
  manipulation_markers: number;
  punctuation_density: number;
  structural_irregularity: number;
  scanned_characters: number;
}

export interface FirewallEvaluation {
  decision: FirewallDecision;
  signals: FirewallSignals;
  sanitized_memo: string;
}

type AttackVector = {
  category: Exclude<ThreatCategory, "NONE" | "STRUCTURAL_ANOMALY">;
  phraseSets: string[][];
  weight: number;
};

const banksimAttackVectors: AttackVector[] = [
  {
    category: "PROMPT_INJECTION",
    phraseSets: [
      ["ignore", "previous", "instructions"],
      ["disregard", "all", "prior", "rules"],
      ["reveal", "the", "hidden", "prompt"],
      ["replace", "your", "system", "instructions"],
      ["follow", "my", "instructions", "instead"],
    ],
    weight: 0.57,
  },
  {
    category: "JAILBREAK",
    phraseSets: [
      ["bypass", "the", "approval", "gate"],
      ["execute", "without", "authorization"],
      ["override", "the", "transaction", "limit"],
      ["call", "the", "transfer", "tool"],
      ["disable", "the", "safety", "check"],
    ],
    weight: 0.61,
  },
  {
    category: "ROLEPLAY_ATTACK",
    phraseSets: [
      ["pretend", "you", "are", "the", "bank", "administrator"],
      ["act", "as", "an", "unrestricted", "operator"],
      ["you", "are", "now", "the", "system"],
      ["roleplay", "as", "a", "privileged", "agent"],
    ],
    weight: 0.55,
  },
  {
    category: "MEMO_INJECTION",
    phraseSets: [
      ["script", "alert"],
      ["script", "fetch"],
      ["javascript", "alert"],
      ["shell", "command"],
      ["run", "this", "payload"],
      ["fetch", "credentials"],
      ["exfiltrate", "account", "details"],
      ["tool", "call", "transfer"],
      ["document", "cookie"],
      ["process", "env"],
      ["eval", "atob"],
      ["curl", "https"],
      ["wget", "https"],
      ["powershell", "encodedcommand"],
      ["invoke", "expression"],
      ["rm", "rf"],
    ],
    weight: 0.6,
  },
];

const banksimDangerousControlCodes = new Set<number>([
  0x00, 0x08, 0x0b, 0x0c, 0x0e, 0x0f, 0x7f, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff,
]);

export function isValidTransferAmount(amount: string | undefined): amount is string {
  if (!amount || amount.length > 12) return false;
  let decimalPointSeen = false;
  let fractionalDigits = 0;
  let wholeDigits = 0;
  for (const character of amount) {
    if (character === "." && !decimalPointSeen) {
      decimalPointSeen = true;
      continue;
    }
    if (character < "0" || character > "9") return false;
    if (decimalPointSeen) fractionalDigits += 1;
    else wholeDigits += 1;
  }
  if (wholeDigits === 0 || fractionalDigits > 2 || (decimalPointSeen && fractionalDigits === 0)) {
    return false;
  }
  const parsedAmount = Number(amount);
  return Number.isFinite(parsedAmount) && parsedAmount > 0 && parsedAmount <= 5000;
}

export function isValidTargetIdentifier(identifier: string | undefined): identifier is string {
  if (!identifier || identifier.length < 4 || identifier.length > 24) return false;
  for (const character of identifier) {
    const isAsciiLetter =
      (character >= "A" && character <= "Z") || (character >= "a" && character <= "z");
    const isAsciiDigit = character >= "0" && character <= "9";
    if (!isAsciiLetter && !isAsciiDigit && character !== "-") return false;
  }
  return true;
}

function banksimTokenize(inputText: string): string[] {
  const normalizedText = inputText.normalize("NFKC").toLocaleLowerCase("en-US");
  const resultingTokens: string[] = [];
  let activeToken = "";

  for (const inputCharacter of normalizedText) {
    if (/[\p{L}\p{N}]/u.test(inputCharacter)) {
      activeToken += inputCharacter;
    } else if (activeToken.length > 0) {
      resultingTokens.push(activeToken);
      activeToken = "";
    }
  }
  if (activeToken.length > 0) resultingTokens.push(activeToken);
  return resultingTokens;
}

function banksimCountPhraseHits(tokens: string[], soughtPhrase: string[]): number {
  let phraseHitCount = 0;
  for (let tokenIndex = 0; tokenIndex <= tokens.length - soughtPhrase.length; tokenIndex += 1) {
    let phraseMatchesAtCursor = true;
    for (let phraseOffset = 0; phraseOffset < soughtPhrase.length; phraseOffset += 1) {
      if (tokens[tokenIndex + phraseOffset] !== soughtPhrase[phraseOffset]) {
        phraseMatchesAtCursor = false;
        break;
      }
    }
    if (phraseMatchesAtCursor) phraseHitCount += 1;
  }
  return phraseHitCount;
}

function banksimInspectStructure(inputText: string): {
  nestingDepth: number;
  unclosedDelimiters: number;
  dangerousControls: number;
  longestCharacterRun: number;
  punctuationDensity: number;
  entropy: number;
  totalCharacters: number;
  ambiguous: boolean;
} {
  const characterFrequencies = new Map<string, number>();
  const delimiterStack: string[] = [];
  const openingToClosingDelimiter = new Map<string, string>([
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
    ["<", ">"],
  ]);
  const closingDelimiters = new Set(["(", ")", "[", "]", "{", "}", "<", ">"]);
  let currentNestingDepth = 0;
  let maximumNestingDepth = 0;
  let dangerousControlCount = 0;
  let punctuationCount = 0;
  let activeCharacterRun = 0;
  let maximumCharacterRun = 0;
  let previousCharacter = "";
  let inspectedCharacterCount = 0;

  for (const character of inputText) {
    inspectedCharacterCount += 1;
    characterFrequencies.set(character, (characterFrequencies.get(character) ?? 0) + 1);
    const characterCode = character.codePointAt(0) ?? 0;

    if (banksimDangerousControlCodes.has(characterCode)) dangerousControlCount += 1;
    if (!/[\p{L}\p{N}\s]/u.test(character)) punctuationCount += 1;

    if (character === previousCharacter) activeCharacterRun += 1;
    else activeCharacterRun = 1;
    maximumCharacterRun = Math.max(maximumCharacterRun, activeCharacterRun);
    previousCharacter = character;

    if (openingToClosingDelimiter.has(character)) {
      delimiterStack.push(openingToClosingDelimiter.get(character) ?? "");
      currentNestingDepth += 1;
      maximumNestingDepth = Math.max(maximumNestingDepth, currentNestingDepth);
    } else if (closingDelimiters.has(character)) {
      if (delimiterStack.at(-1) !== character) {
        if (character !== ">" || delimiterStack.length === 0) {
          currentNestingDepth += 1;
          maximumNestingDepth = Math.max(maximumNestingDepth, currentNestingDepth);
        }
      } else {
        delimiterStack.pop();
        currentNestingDepth = Math.max(0, currentNestingDepth - 1);
      }
    }
  }

  let characterEntropy = 0;
  for (const frequency of characterFrequencies.values()) {
    const characterProbability = frequency / Math.max(inspectedCharacterCount, 1);
    characterEntropy -= characterProbability * Math.log2(characterProbability);
  }
  const normalizedEntropy = Math.min(characterEntropy / 5.2, 1);
  const punctuationDensity = punctuationCount / Math.max(inspectedCharacterCount, 1);
  const unclosedDelimiterCount = delimiterStack.length;
  const isAmbiguous =
    inspectedCharacterCount > 1800 ||
    maximumNestingDepth > 8 ||
    unclosedDelimiterCount > 0 ||
    dangerousControlCount > 0 ||
    maximumCharacterRun > 36;

  return {
    nestingDepth: maximumNestingDepth,
    unclosedDelimiters: unclosedDelimiterCount,
    dangerousControls: dangerousControlCount,
    longestCharacterRun: maximumCharacterRun,
    punctuationDensity,
    entropy: normalizedEntropy,
    totalCharacters: inspectedCharacterCount,
    ambiguous: isAmbiguous,
  };
}

function banksimSanitizeMemo(memoText: string): string {
  let sanitizedText = "";
  for (const character of memoText.normalize("NFKC")) {
    const characterCode = character.codePointAt(0) ?? 0;
    if (!banksimDangerousControlCodes.has(characterCode)) sanitizedText += character;
  }
  return sanitizedText.trim().replace(/\s+/gu, " ");
}

export function evaluateBankSimFirewall(
  incomingRequest: FirewallRequest,
): FirewallEvaluation {
  const combinedInput = [
    incomingRequest.target_tool,
    incomingRequest.amount ?? "",
    incomingRequest.target_identifier ?? "",
    incomingRequest.memo,
  ].join(" ");
  const structuralReadout = banksimInspectStructure(combinedInput);
  const invalidTransferEnvelope =
    incomingRequest.target_tool === "TRANSFER_SIMULATION" &&
    (!isValidTransferAmount(incomingRequest.amount) ||
      !isValidTargetIdentifier(incomingRequest.target_identifier));
  const failSafeBoundaryRequired = structuralReadout.ambiguous || invalidTransferEnvelope;
  const combinedTokens = banksimTokenize(combinedInput);
  const phraseHitByCategory = new Map<AttackVector["category"], number>();
  let markerCount = 0;

  for (const vector of banksimAttackVectors) {
    let vectorHitCount = 0;
    for (const soughtPhrase of vector.phraseSets) {
      vectorHitCount += banksimCountPhraseHits(combinedTokens, soughtPhrase);
    }
    if (vectorHitCount > 0) phraseHitByCategory.set(vector.category, vectorHitCount);
    markerCount += vectorHitCount;
  }

  const memoTokens = banksimTokenize(incomingRequest.memo);
  let memoCommandMarkers = 0;
  for (const commandPhrase of banksimAttackVectors[3].phraseSets) {
    memoCommandMarkers += banksimCountPhraseHits(memoTokens, commandPhrase);
  }

  const manipulationWeight = Math.min(
    [...phraseHitByCategory.entries()].reduce((weightTotal, [category, hits]) => {
      const vectorWeight =
        banksimAttackVectors.find((vector) => vector.category === category)?.weight ?? 0;
      return weightTotal + Math.min(hits, 3) * vectorWeight;
    }, 0),
    1,
  );
  const punctuationRisk = Math.max(0, structuralReadout.punctuationDensity - 0.22) * 0.48;
  const entropyRisk = Math.max(0, structuralReadout.entropy - 0.68) * 0.24;
  const lengthRisk = Math.min(structuralReadout.totalCharacters / 5000, 0.18);
  const repeatedPatternRisk = structuralReadout.longestCharacterRun > 12 ? 0.24 : 0;
  const structuralWeight = failSafeBoundaryRequired ? 1 : 0;
  const customRiskCalculation =
    1 -
    (1 - manipulationWeight) *
      (1 - punctuationRisk) *
      (1 - entropyRisk) *
      (1 - lengthRisk) *
      (1 - repeatedPatternRisk);
  const riskScore = Number(Math.min(1, Math.max(structuralWeight, customRiskCalculation)).toFixed(4));

  let threatCategory: ThreatCategory = "NONE";
  if (failSafeBoundaryRequired) {
    threatCategory = "STRUCTURAL_ANOMALY";
  } else if (phraseHitByCategory.has("PROMPT_INJECTION")) {
    threatCategory = "PROMPT_INJECTION";
  } else if (phraseHitByCategory.has("ROLEPLAY_ATTACK")) {
    threatCategory = "ROLEPLAY_ATTACK";
  } else if (phraseHitByCategory.has("JAILBREAK")) {
    threatCategory = "JAILBREAK";
  } else if (memoCommandMarkers > 0) {
    threatCategory = "MEMO_INJECTION";
  }

  const shouldBlock = failSafeBoundaryRequired || riskScore >= 0.44;
  const status = shouldBlock ? "BLOCKED" : "APPROVED";
  const explanation = shouldBlock
    ? structuralReadout.ambiguous
      ? "Fail-safe boundary engaged: the request contains an invalid transaction envelope, ambiguous structure, or an anomalous character pattern, so no banking action may proceed."
      : `${threatCategory.replaceAll("_", " ")} pattern detected across ${markerCount} structural marker${markerCount === 1 ? "" : "s"}; the request was isolated before routing to a banking tool.`
    : "Input structure is within the simulator's bounded envelope; the allowlisted request may proceed to a server-validated BankSim simulation.";

  return {
    decision: {
      status,
      risk_score: riskScore,
      threat_category: threatCategory,
      explanation,
    },
    signals: {
      character_entropy: Number(structuralReadout.entropy.toFixed(4)),
      manipulation_markers: markerCount,
      punctuation_density: Number(structuralReadout.punctuationDensity.toFixed(4)),
      structural_irregularity: failSafeBoundaryRequired ? 1 : 0,
      scanned_characters: structuralReadout.totalCharacters,
    },
    sanitized_memo: banksimSanitizeMemo(incomingRequest.memo),
  };
}
