const FLOWCHART_DECLARATION = /^\s*(?:graph|flowchart)\b/i;
const SKIP_LINE_PATTERN =
  /^\s*(?:%%|classDef\b|class\b|style\b|linkStyle\b|click\b|subgraph\b|end\b|direction\b|accTitle:|accDescr:)/i;

type NodePattern = {
  pattern: RegExp;
  open: string;
  close: string;
};

const NODE_PATTERNS: NodePattern[] = [
  {
    pattern: /(^|[\s>|])([A-Za-z_][A-Za-z0-9_]*)\{([^{}]*?)\}/gm,
    open: "{",
    close: "}",
  },
  {
    pattern: /(^|[\s>|])([A-Za-z_][A-Za-z0-9_]*)\[([^[\]]*?)\]/gm,
    open: "[",
    close: "]",
  },
];

function isQuotedLabel(label: string) {
  return /^".*"$/.test(label.trim());
}

function quoteLabel(label: string) {
  const trimmed = label.trim();
  if (!trimmed || isQuotedLabel(trimmed)) {
    return trimmed;
  }

  const escaped = trimmed.replace(/"/g, "&quot;").replace(/\r?\n/g, "<br/>");
  return `"${escaped}"`;
}

function normalizeEdgeLabels(line: string) {
  return line.replace(/\|([^|\n]+)\|/g, (match, label: string) => {
    const trimmed = label.trim();
    if (!trimmed) {
      return match;
    }
    return `|${quoteLabel(trimmed)}|`;
  });
}

function normalizeNodeLabels(line: string) {
  let normalized = line;

  for (const { pattern, open, close } of NODE_PATTERNS) {
    normalized = normalized.replace(
      pattern,
      (match, prefix: string, id: string, label: string) => {
        const trimmed = label.trim();
        if (!trimmed) {
          return match;
        }
        return `${prefix}${id}${open}${quoteLabel(trimmed)}${close}`;
      },
    );
  }

  return normalized;
}

export function normalizeMermaidCode(code: string) {
  const hasCRLF = code.includes("\r\n");
  const lines = code.replace(/\r\n/g, "\n").split("\n");
  const declarationIndex = lines.findIndex((line) =>
    FLOWCHART_DECLARATION.test(line.trim()),
  );

  if (declarationIndex === -1) {
    return code;
  }

  const normalized = lines
    .map((line, index) => {
      if (index < declarationIndex) {
        return line;
      }

      const trimmed = line.trim();
      if (!trimmed || SKIP_LINE_PATTERN.test(trimmed)) {
        return line;
      }

      return normalizeNodeLabels(normalizeEdgeLabels(line));
    })
    .join("\n");

  return hasCRLF ? normalized.replace(/\n/g, "\r\n") : normalized;
}
