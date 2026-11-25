use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordGenOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseGenOptions {
    pub word_count: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseGenOptions {
    fn default() -> Self {
        Self {
            word_count: 6,
            separator: "-".to_string(),
            capitalize: true,
            include_number: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub entropy_bits: f64,
    /// Effective post-quantum security margin under Grover's algorithm (bits / 2).
    pub post_quantum_bits: f64,
    pub strength: String,
    pub score: u8, // 0..=100
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedSecret {
    pub value: String,
    #[zeroize(skip)]
    pub entropy: EntropyReport,
}

impl std::fmt::Debug for GeneratedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedSecret")
            .field("value", &"[REDACTED]")
            .field("entropy", &self.entropy)
            .finish()
    }
}

/// Unbiased uniform index in `0..upper` using CSPRNG (`OsRng`) with rejection sampling.
fn csprng_index(upper: usize) -> usize {
    assert!(upper > 0);
    let upper_u64 = upper as u64;
    let zone = u64::MAX - (u64::MAX % upper_u64);
    loop {
        let r = OsRng.next_u64();
        if r < zone {
            return (r % upper_u64) as usize;
        }
    }
}

/// Generate a cryptographically secure random password using `OsRng`.
pub fn generate_password(opts: &PasswordGenOptions) -> GeneratedSecret {
    let length = opts.length.clamp(8, 128);
    let ambiguous = "0O1lI|`'\"";

    let filter = |s: &str| -> Vec<char> {
        s.chars()
            .filter(|c| !opts.exclude_ambiguous || !ambiguous.contains(*c))
            .collect()
    };

    let mut groups: Vec<Vec<char>> = Vec::new();
    if opts.lowercase {
        groups.push(filter("abcdefghijklmnopqrstuvwxyz"));
    }
    if opts.uppercase {
        groups.push(filter("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }
    if opts.digits {
        groups.push(filter("0123456789"));
    }
    if opts.symbols {
        groups.push(filter("!@#$%^&*()-_=+[]{}.,:;?~"));
    }
    if groups.is_empty() {
        groups.push(filter("abcdefghijklmnopqrstuvwxyz"));
        groups.push(filter("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        groups.push(filter("0123456789"));
    }

    let pool: Vec<u8> = groups
        .iter()
        .flatten()
        .map(|c| *c as u8)
        .collect();
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));

    // Guarantee at least one character from each enabled class
    for grp in &groups {
        if bytes.len() < length && !grp.is_empty() {
            bytes.push(grp[csprng_index(grp.len())] as u8);
        }
    }
    while bytes.len() < length {
        bytes.push(pool[csprng_index(pool.len())]);
    }

    // Fisher-Yates shuffle using CSPRNG
    for i in (1..bytes.len()).rev() {
        let j = csprng_index(i + 1);
        bytes.swap(i, j);
    }

    let value = String::from_utf8(bytes.to_vec()).expect("ASCII password pool is valid UTF-8");
    let exact_bits = (length as f64) * (pool.len() as f64).log2();
    let entropy = build_entropy_report(exact_bits);

    GeneratedSecret { value, entropy }
}

/// Generate a Diceware passphrase from the embedded 520-word CSPRNG wordlist (>9 bits/word).
pub fn generate_passphrase(opts: &PassphraseGenOptions) -> GeneratedSecret {
    let count = opts.word_count.clamp(4, 12);
    let mut words: Vec<String> = Vec::with_capacity(count);

    for _ in 0..count {
        let raw = DICEWARE_WORDS[csprng_index(DICEWARE_WORDS.len())];
        let word = if opts.capitalize {
            let mut ch = raw.chars();
            match ch.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), ch.as_str()),
                None => String::new(),
            }
        } else {
            raw.to_string()
        };
        words.push(word);
    }

    let mut extra_bits = 0.0;
    if opts.include_number {
        let num = csprng_index(1000);
        let idx = csprng_index(words.len());
        words[idx].push_str(&format!("{num:03}"));
        extra_bits = (1000.0_f64).log2();
    }

    let sep = if opts.separator.is_empty() {
        "-"
    } else {
        &opts.separator
    };
    let value = words.join(sep);
    for w in &mut words {
        w.zeroize();
    }
    let bits = (count as f64) * (DICEWARE_WORDS.len() as f64).log2() + extra_bits;

    GeneratedSecret {
        value,
        entropy: build_entropy_report(bits),
    }
}

/// Evaluate the estimated entropy of an arbitrary user-provided password.
pub fn evaluate_password(password: &str) -> EntropyReport {
    if password.is_empty() {
        return build_entropy_report(0.0);
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c == ' ');
    let has_unicode = !password.is_ascii();

    let mut pool = 0usize;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 33;
    }
    if has_unicode {
        pool += 128;
    }
    pool = pool.max(1);

    let len = password.chars().count();
    let mut bits = (len as f64) * (pool as f64).log2();

    // Penalize obvious low-entropy patterns (repetitions / common weak words)
    let lower = Zeroizing::new(password.to_ascii_lowercase());
    let common_weak = [
        "password", "123456", "qwerty", "admin", "letmein", "welcome", "cipher", "pass123",
    ];
    if common_weak.iter().any(|w| lower.contains(w)) {
        bits *= 0.45;
    }

    let unique_chars: std::collections::HashSet<char> = password.chars().collect();
    if unique_chars.len() * 2 < len {
        bits *= 0.65;
    }

    build_entropy_report(bits)
}

fn build_entropy_report(bits: f64) -> EntropyReport {
    let entropy_bits = (bits * 10.0).round() / 10.0;
    let post_quantum_bits = (bits * 5.0).round() / 10.0; // bits / 2 rounded to 1 decimal

    let (strength, score) = if bits < 40.0 {
        ("Critical / Weak", ((bits / 40.0) * 25.0) as u8)
    } else if bits < 65.0 {
        ("Fair", (25.0 + ((bits - 40.0) / 25.0) * 25.0) as u8)
    } else if bits < 95.0 {
        ("Strong", (50.0 + ((bits - 65.0) / 30.0) * 25.0) as u8)
    } else if bits < 128.0 {
        ("Very Strong", (75.0 + ((bits - 95.0) / 33.0) * 15.0) as u8)
    } else {
        (
            "Post-Quantum Grade",
            (90.0 + ((bits - 128.0).min(64.0) / 64.0) * 10.0) as u8,
        )
    };

    EntropyReport {
        entropy_bits,
        post_quantum_bits,
        strength: strength.to_string(),
        score: score.min(100),
    }
}

/// Curated 520-word unambiguous Diceware wordlist (>9.0 bits of entropy per word).
const DICEWARE_WORDS: &[&str] = &[
    "acorn",
    "admire",
    "aegis",
    "agate",
    "alder",
    "alibi",
    "alloy",
    "almond",
    "amber",
    "anchor",
    "anise",
    "anvil",
    "apex",
    "apricot",
    "arbor",
    "arcade",
    "arctic",
    "argon",
    "armor",
    "arrow",
    "aspen",
    "aster",
    "atlas",
    "atoll",
    "aurora",
    "autumn",
    "avalanche",
    "axiom",
    "azalea",
    "azure",
    "badge",
    "badger",
    "bamboo",
    "banjo",
    "banyan",
    "barley",
    "basalt",
    "basin",
    "beacon",
    "beaver",
    "belfry",
    "bellow",
    "beryl",
    "birch",
    "bison",
    "blade",
    "blazer",
    "blizzard",
    "blossom",
    "bobcat",
    "bolero",
    "bonsai",
    "boulder",
    "bramble",
    "breeze",
    "briar",
    "bridge",
    "brigade",
    "bristle",
    "bronze",
    "brook",
    "bucket",
    "buckler",
    "buffalo",
    "bulwark",
    "buoy",
    "burrow",
    "cactus",
    "cadence",
    "cairn",
    "caliber",
    "calico",
    "callow",
    "camber",
    "camel",
    "camphor",
    "canary",
    "candle",
    "canopy",
    "canyon",
    "capstan",
    "caramel",
    "carbon",
    "caribou",
    "carmine",
    "carol",
    "cascade",
    "cashew",
    "castle",
    "catalpa",
    "cavern",
    "cedar",
    "celery",
    "celeste",
    "cellar",
    "cenote",
    "chalice",
    "chalk",
    "chamois",
    "channel",
    "chapel",
    "chariot",
    "charter",
    "chasm",
    "cherry",
    "chestnut",
    "chime",
    "chimney",
    "chisel",
    "choral",
    "chrome",
    "cinder",
    "cinema",
    "cinnamon",
    "cipher",
    "circle",
    "cirrus",
    "citadel",
    "citron",
    "citrus",
    "claret",
    "clarion",
    "clasp",
    "cleaver",
    "cliff",
    "climax",
    "clinker",
    "clove",
    "clover",
    "cluster",
    "cobalt",
    "cobra",
    "cockpit",
    "cocoa",
    "codex",
    "coffee",
    "cognac",
    "coil",
    "collie",
    "column",
    "comet",
    "compass",
    "concord",
    "condor",
    "conifer",
    "console",
    "consul",
    "copper",
    "coral",
    "cordial",
    "cornet",
    "corona",
    "corral",
    "corsair",
    "cortex",
    "cosmos",
    "cottage",
    "cougar",
    "courier",
    "coven",
    "covey",
    "coyote",
    "cradle",
    "crane",
    "crater",
    "crayon",
    "creek",
    "crescent",
    "crest",
    "cricket",
    "crimson",
    "crocus",
    "croquet",
    "crown",
    "crucible",
    "cruise",
    "crystal",
    "cuboid",
    "cuckoo",
    "culvert",
    "cumulus",
    "cupola",
    "curfew",
    "curlew",
    "currant",
    "curtain",
    "cushion",
    "cutlass",
    "cyclone",
    "cygnet",
    "cymbal",
    "cypress",
    "dagger",
    "dahlia",
    "dainty",
    "damask",
    "damson",
    "dancer",
    "dapple",
    "darling",
    "darter",
    "daybreak",
    "deacon",
    "decade",
    "decibel",
    "decoy",
    "deluge",
    "denim",
    "depot",
    "derby",
    "desert",
    "despot",
    "diadem",
    "dial",
    "diamond",
    "diatom",
    "diesel",
    "digger",
    "dinghy",
    "diode",
    "diorama",
    "dipper",
    "dirge",
    "discus",
    "diver",
    "dolmen",
    "dolphin",
    "domain",
    "domino",
    "donkey",
    "dorado",
    "dormer",
    "dorsal",
    "dory",
    "doublet",
    "dragon",
    "drake",
    "draper",
    "drawer",
    "drift",
    "drizzle",
    "dromedary",
    "droplet",
    "druid",
    "drummer",
    "dryad",
    "ducat",
    "duchess",
    "dugong",
    "dulcet",
    "dumper",
    "dungeon",
    "duplex",
    "durian",
    "duster",
    "dynamo",
    "eagle",
    "earwig",
    "easel",
    "ebony",
    "echo",
    "eclipse",
    "eddy",
    "edifice",
    "egret",
    "eider",
    "elder",
    "elegy",
    "element",
    "elfin",
    "elixir",
    "elm",
    "emblem",
    "emerald",
    "emery",
    "emissary",
    "empire",
    "enamel",
    "enclave",
    "encore",
    "endive",
    "engine",
    "enigma",
    "ensign",
    "entree",
    "epoch",
    "equinox",
    "ermine",
    "errand",
    "escort",
    "esparto",
    "estuary",
    "etching",
    "ether",
    "eulogy",
    "eureka",
    "evening",
    "evergreen",
    "exarch",
    "exile",
    "exodus",
    "expanse",
    "exploit",
    "eyrie",
    "fable",
    "fabric",
    "facade",
    "facet",
    "factor",
    "faucet",
    "falcon",
    "fallow",
    "fanfare",
    "fang",
    "fantom",
    "farad",
    "farrow",
    "fathom",
    "fauna",
    "feather",
    "fedora",
    "feline",
    "felloe",
    "felspar",
    "fender",
    "fennel",
    "ferret",
    "ferrule",
    "ferry",
    "festoon",
    "fettle",
    "fiber",
    "fibula",
    "fiddle",
    "fiefdom",
    "fiesta",
    "figment",
    "filbert",
    "filigree",
    "fillet",
    "filter",
    "finale",
    "finch",
    "finder",
    "finial",
    "firkin",
    "firth",
    "fissure",
    "flagon",
    "flail",
    "flambe",
    "flamboyant",
    "flame",
    "flange",
    "flannel",
    "flash",
    "flask",
    "flaxen",
    "fleece",
    "fletcher",
    "flicker",
    "flint",
    "flipper",
    "floe",
    "flora",
    "floret",
    "florin",
    "flotsam",
    "flounder",
    "flourish",
    "flower",
    "flume",
    "flurry",
    "flute",
    "flux",
    "flyway",
    "foal",
    "focus",
    "fodder",
    "foible",
    "folder",
    "foliage",
    "folio",
    "fondant",
    "fondue",
    "font",
    "forage",
    "foray",
    "ford",
    "forest",
    "forge",
    "forger",
    "format",
    "formula",
    "fortress",
    "forum",
    "fossil",
    "foster",
    "foundry",
    "fountain",
    "foxglove",
    "foxhound",
    "fractal",
    "fragment",
    "frame",
    "franc",
    "frigate",
    "fringe",
    "fritter",
    "frizzle",
    "frond",
    "frost",
    "froth",
    "frown",
    "fructose",
    "frugal",
    "fruit",
    "fugue",
    "fulcrum",
    "fulmar",
    "fumble",
    "funnel",
    "furlong",
    "furnace",
    "furrow",
    "fusion",
    "fustian",
    "futon",
    "future",
    "gable",
    "gadget",
    "gaffer",
    "gaggle",
    "gaiety",
    "gaiter",
    "galaxy",
    "galena",
    "galley",
    "gallon",
    "gallop",
    "gambit",
    "gambol",
    "gamut",
    "gander",
    "gangway",
    "gannet",
    "gantry",
    "garage",
    "garble",
    "garden",
    "gargoyle",
    "garland",
    "garlic",
    "garment",
    "garner",
    "garnet",
    "garret",
    "garrison",
    "garter",
    "gasket",
    "gauntlet",
    "gauze",
    "gavel",
    "gavotte",
    "gazelle",
    "gazette",
    "gearbox",
    "gecko",
    "geisha",
    "gelatin",
    "gelding",
    "gemini",
    "gemstone",
    "gender",
    "genesis",
    "genial",
    "genome",
    "genre",
    "gentian",
    "geode",
    "gerbil",
    "geyser",
    "ghoul",
    "gibbon",
    "giblet",
    "giddy",
    "giggle",
    "gilder",
    "gimbal",
    "gimlet",
    "ginger",
    "gingham",
    "ginkgo",
    "giraffe",
    "girder",
    "girdle",
    "glacier",
    "glade",
    "glamour",
    "glance",
    "gland",
    "glaze",
    "gleam",
    "gleaner",
    "glider",
    "glimmer",
    "glint",
    "glitter",
    "gloaming",
    "globule",
    "glory",
    "gloss",
    "glove",
    "glucose",
    "gluten",
    "glyph",
    "gnarled",
    "gnome",
    "goblet",
    "goblin",
];
