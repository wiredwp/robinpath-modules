import type { BuiltinHandler } from "@wiredwp/robinpath";

// --- Pure JS XML helpers (no npm packages) ---

function getTagContent(xml: string, tag: string): string {
  // Match <tag ...>content</tag>, handling CDATA
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const m = xml.match(re);
  if (!m) return "";
  return decodeCDATA(m[1]).trim();
}

function getAttr(xml: string, attr: string): string {
  const re = new RegExp(`${attr}\\s*=\\s*["']([^"']*)["']`, "i");
  const m = xml.match(re);
  return m ? m[1] : "";
}

function decodeCDATA(s: string): string {
  return s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'");
}

function stripTags(html: string): string {
  return html.replace(/<[^>]*>/g, "").trim();
}

function getAllMatches(xml: string, openTag: string, closeTag: string): string[] {
  const results: string[] = [];
  let idx = 0;
  while (true) {
    const start = xml.indexOf(`<${openTag}`, idx);
    if (start === -1) break;
    const end = xml.indexOf(closeTag, start);
    if (end === -1) break;
    results.push(xml.slice(start, end + closeTag.length));
    idx = end + closeTag.length;
  }
  return results;
}

function getCategories(itemXml: string): string[] {
  const cats: string[] = [];
  const re = /<category[^>]*>([\s\S]*?)<\/category>/gi;
  let m;
  while ((m = re.exec(itemXml)) !== null) {
    const val = decodeCDATA(m[1]).trim();
    if (val) cats.push(decodeEntities(val));
  }
  // Atom: <category term="..."/>
  const re2 = /<category[^>]*term\s*=\s*["']([^"']*)["'][^>]*\/?>/gi;
  while ((m = re2.exec(itemXml)) !== null) {
    const val = m[1].trim();
    if (val && !cats.includes(val)) cats.push(decodeEntities(val));
  }
  return cats;
}

interface ParsedFeed {
  title: string;
  description: string;
  link: string;
  language: string;
  lastBuildDate: string;
  items: ParsedItem[];
}

interface ParsedItem {
  title: string;
  link: string;
  pubDate: string;
  content: string;
  author: string;
  categories: string[];
  guid: string;
}

function isAtomFeed(xml: string): boolean {
  return /<feed[\s>]/i.test(xml);
}

function parseAtomEntry(entryXml: string): ParsedItem {
  const title = decodeEntities(getTagContent(entryXml, "title"));

  // Atom links: <link href="..." rel="alternate"/> or <link href="..."/>
  let link = "";
  const linkAlt = entryXml.match(/<link[^>]*rel\s*=\s*["']alternate["'][^>]*href\s*=\s*["']([^"']*)["'][^>]*\/?>/i);
  const linkAlt2 = entryXml.match(/<link[^>]*href\s*=\s*["']([^"']*)["'][^>]*rel\s*=\s*["']alternate["'][^>]*\/?>/i);
  const linkPlain = entryXml.match(/<link[^>]*href\s*=\s*["']([^"']*)["'][^>]*\/?>/i);
  if (linkAlt) link = linkAlt[1];
  else if (linkAlt2) link = linkAlt2[1];
  else if (linkPlain) link = linkPlain[1];

  const published = getTagContent(entryXml, "published") || getTagContent(entryXml, "updated");
  const content = getTagContent(entryXml, "content") || getTagContent(entryXml, "summary");
  const author = getTagContent(entryXml, "name") || ""; // inside <author><name>
  const guid = getTagContent(entryXml, "id") || link;
  const categories = getCategories(entryXml);

  return {
    title,
    link: decodeEntities(link),
    pubDate: published,
    content: stripTags(decodeEntities(content)),
    author: decodeEntities(author),
    categories,
    guid: decodeEntities(guid),
  };
}

function parseRssItem(itemXml: string): ParsedItem {
  const title = decodeEntities(getTagContent(itemXml, "title"));
  const link = decodeEntities(getTagContent(itemXml, "link"));
  const pubDate = getTagContent(itemXml, "pubDate");
  const contentEncoded = getTagContent(itemXml, "content:encoded");
  const description = getTagContent(itemXml, "description");
  const content = contentEncoded || description;
  const author = getTagContent(itemXml, "dc:creator") || getTagContent(itemXml, "author");
  const guid = getTagContent(itemXml, "guid") || link;
  const categories = getCategories(itemXml);

  return {
    title,
    link,
    pubDate,
    content: stripTags(decodeEntities(content)),
    author: decodeEntities(author),
    categories,
    guid: decodeEntities(guid),
  };
}

function parseFeedXml(xml: string): ParsedFeed {
  if (isAtomFeed(xml)) {
    // Atom feed
    const title = decodeEntities(getTagContent(xml, "title"));
    const subtitle = decodeEntities(getTagContent(xml, "subtitle"));

    // Feed-level link
    let link = "";
    const feedLinkAlt = xml.match(/<link[^>]*rel\s*=\s*["']alternate["'][^>]*href\s*=\s*["']([^"']*)["'][^>]*\/?>/i);
    const feedLinkPlain = xml.match(/<link[^>]*href\s*=\s*["']([^"']*)["'][^>]*\/?>/i);
    if (feedLinkAlt) link = feedLinkAlt[1];
    else if (feedLinkPlain) link = feedLinkPlain[1];

    const updated = getTagContent(xml, "updated");
    const entries = getAllMatches(xml, "entry", "</entry>");
    const items = entries.map(parseAtomEntry);

    return {
      title,
      description: subtitle,
      link: decodeEntities(link),
      language: "",
      lastBuildDate: updated,
      items,
    };
  }

  // RSS 2.0
  const channelMatch = xml.match(/<channel>([\s\S]*)<\/channel>/i);
  const channel = channelMatch ? channelMatch[1] : xml;

  const title = decodeEntities(getTagContent(channel, "title"));
  const description = decodeEntities(getTagContent(channel, "description"));
  const link = decodeEntities(getTagContent(channel, "link"));
  const language = getTagContent(channel, "language");
  const lastBuildDate = getTagContent(channel, "lastBuildDate");

  const items = getAllMatches(channel, "item", "</item>").map(parseRssItem);

  return { title, description, link, language, lastBuildDate, items };
}

async function fetchFeed(url: string): Promise<ParsedFeed> {
  const res = await fetch(url, {
    headers: {
      "User-Agent": "RobinPath-RSS/1.0",
      Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    },
  });
  if (!res.ok) throw new Error(`Failed to fetch feed: ${res.status} ${res.statusText}`);
  const xml = await res.text();
  return parseFeedXml(xml);
}

// --- State ---

const feedCache = new Map<string, { items: ParsedItem[]; lastFetched: number }>();

// --- Handlers ---

const parse: BuiltinHandler = async (args) => {
  const url = String(args[0] ?? "");
  const feed = await fetchFeed(url);
  feedCache.set(url, { items: feed.items, lastFetched: Date.now() });
  return {
    title: feed.title,
    description: feed.description,
    link: feed.link,
    language: feed.language,
    lastBuildDate: feed.lastBuildDate,
    items: feed.items.map((i) => ({
      title: i.title,
      link: i.link,
      pubDate: i.pubDate,
      content: i.content,
      author: i.author,
      categories: i.categories,
      guid: i.guid,
    })),
  };
};

const parseString: BuiltinHandler = async (args) => {
  const xml = String(args[0] ?? "");
  const feed = parseFeedXml(xml);
  return {
    title: feed.title,
    description: feed.description,
    items: feed.items.map((i) => ({
      title: i.title,
      link: i.link,
      pubDate: i.pubDate,
      content: i.content,
      author: i.author,
    })),
  };
};

const getItems: BuiltinHandler = async (args) => {
  const url = String(args[0] ?? "");
  const limit = parseInt(String(args[1] ?? "10"), 10);
  const feed = await fetchFeed(url);
  return feed.items.slice(0, limit).map((i) => ({
    title: i.title,
    link: i.link,
    pubDate: i.pubDate,
    content: i.content,
    author: i.author,
  }));
};

const getNew: BuiltinHandler = async (args) => {
  const url = String(args[0] ?? "");
  const since = args[1] != null ? new Date(String(args[1])).getTime() : undefined;
  const cached = feedCache.get(url);
  const feed = await fetchFeed(url);
  const currentItems = feed.items.map((i) => ({
    title: i.title,
    link: i.link,
    pubDate: i.pubDate,
    content: i.content,
    guid: i.guid,
  }));

  let newItems;
  if (since) {
    newItems = currentItems.filter((i) => i.pubDate && new Date(i.pubDate).getTime() > since);
  } else if (cached) {
    const cachedGuids = new Set(cached.items.map((i) => i.guid ?? i.link));
    newItems = currentItems.filter((i) => !cachedGuids.has(i.guid ?? i.link));
  } else {
    newItems = currentItems;
  }

  feedCache.set(url, { items: feed.items, lastFetched: Date.now() });
  return newItems;
};

const getLatest: BuiltinHandler = async (args) => {
  const url = String(args[0] ?? "");
  const feed = await fetchFeed(url);
  const item = feed.items[0];
  if (!item) return null;
  return {
    title: item.title,
    link: item.link,
    pubDate: item.pubDate,
    content: item.content,
    author: item.author,
  };
};

const feedInfo: BuiltinHandler = async (args) => {
  const url = String(args[0] ?? "");
  const feed = await fetchFeed(url);
  return {
    title: feed.title,
    description: feed.description,
    link: feed.link,
    language: feed.language,
    lastBuildDate: feed.lastBuildDate,
    itemCount: feed.items.length,
  };
};

// --- Exports ---

export const RssFunctions: Record<string, BuiltinHandler> = { parse, parseString, getItems, getNew, getLatest, feedInfo };

export const RssFunctionMetadata = {
  parse: { description: "Parse an RSS/Atom feed from a URL", parameters: [{ name: "url", dataType: "string", description: "Feed URL", formInputType: "text", required: true }], returnType: "object", returnDescription: "{title, description, link, items}", example: 'rss.parse "https://blog.example.com/feed"' },
  parseString: { description: "Parse RSS/Atom XML from a string", parameters: [{ name: "xml", dataType: "string", description: "XML content", formInputType: "text", required: true }], returnType: "object", returnDescription: "{title, items}", example: 'rss.parseString $xmlContent' },
  getItems: { description: "Get feed items with a limit", parameters: [{ name: "url", dataType: "string", description: "Feed URL", formInputType: "text", required: true }, { name: "limit", dataType: "number", description: "Max items (default 10)", formInputType: "text", required: false }], returnType: "array", returnDescription: "Array of items", example: 'rss.getItems "https://blog.example.com/feed" 5' },
  getNew: { description: "Get only new items since last check or since a date", parameters: [{ name: "url", dataType: "string", description: "Feed URL", formInputType: "text", required: true }, { name: "since", dataType: "string", description: "ISO date (optional, uses cache if omitted)", formInputType: "text", required: false }], returnType: "array", returnDescription: "Array of new items", example: 'rss.getNew "https://blog.example.com/feed" "2025-01-01"' },
  getLatest: { description: "Get the most recent item from a feed", parameters: [{ name: "url", dataType: "string", description: "Feed URL", formInputType: "text", required: true }], returnType: "object", returnDescription: "Latest item or null", example: 'rss.getLatest "https://blog.example.com/feed"' },
  feedInfo: { description: "Get feed metadata without items", parameters: [{ name: "url", dataType: "string", description: "Feed URL", formInputType: "text", required: true }], returnType: "object", returnDescription: "{title, description, link, itemCount}", example: 'rss.feedInfo "https://blog.example.com/feed"' },
};

export const RssModuleMetadata = {
  description: "Parse RSS and Atom feeds, detect new entries, and get feed metadata",
  methods: ["parse", "parseString", "getItems", "getNew", "getLatest", "feedInfo"],
};
