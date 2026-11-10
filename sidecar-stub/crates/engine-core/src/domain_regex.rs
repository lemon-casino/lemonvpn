//! Bounded OR matching for genuine domain regexes, independent of source size.
//! Ordinary exact/suffix domains belong in their string indices, never here.
const SHARD_BYTES: usize = 4 * 1024 * 1024;
const CACHE_BYTES: usize = 256 * 1024;
const MAX_SHARDS: usize = 16;
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const BATCH_PATTERNS: usize = 4096;

#[derive(Default)]
pub(crate) struct RegexIndex {
    shards: Vec<regex::RegexSet>,
}
impl RegexIndex {
    pub(crate) fn build(mut patterns: Vec<String>) -> Result<Self, String> {
        patterns.sort_unstable();
        patterns.dedup();
        let bytes = patterns.iter().try_fold(0usize, |sum, value| {
            sum.checked_add(value.len())
                .filter(|n| *n <= MAX_SOURCE_BYTES)
        });
        if bytes.is_none() {
            return Err("正则内容超过 16 MiB，请拆分规则集".into());
        }
        let mut index = Self::default();
        for chunk in patterns.chunks(BATCH_PATTERNS) {
            index.append(chunk)?;
        }
        Ok(index)
    }
    fn append(&mut self, patterns: &[String]) -> Result<(), String> {
        if self.shards.len() >= MAX_SHARDS {
            return Err("正则索引总量超限，请拆分规则集".into());
        }
        match regex::RegexSetBuilder::new(patterns)
            .case_insensitive(true)
            .size_limit(SHARD_BYTES)
            .dfa_size_limit(CACHE_BYTES)
            .build()
        {
            Ok(set) => {
                self.shards.push(set);
                Ok(())
            }
            Err(regex::Error::CompiledTooBig(_)) if patterns.len() > 1 => {
                let mid = patterns.len() / 2;
                self.append(&patterns[..mid])?;
                self.append(&patterns[mid..])
            }
            Err(regex::Error::CompiledTooBig(_)) => {
                Err("单条正则过于复杂，编译后超过 4 MiB".into())
            }
            Err(error) => Err(format!("正则无效：{error}")),
        }
    }
    pub(crate) fn is_match(&self, host: &str) -> bool {
        self.shards.iter().any(|set| set.is_match(host))
    }
    pub(crate) fn patterns(&self) -> impl Iterator<Item = &str> {
        self.shards
            .iter()
            .flat_map(|set| set.patterns().iter().map(String::as_str))
    }
}
