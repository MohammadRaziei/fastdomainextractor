use ahash::{AHashMap, AHashSet};
use std::env;

struct Suffix {
    sub_suffixes: AHashMap<String, Suffix>,
    is_wildcard: bool,
    sub_blacklist: AHashSet<String>,
}

impl Suffix {
    fn new() -> Self {
        Self {
            sub_suffixes: AHashMap::new(),
            is_wildcard: false,
            sub_blacklist: AHashSet::new(),
        }
    }
}

struct DomainExtractor {
    suffixes: AHashMap<String, Suffix>,
}

impl DomainExtractor {
    fn new() -> Self {
        Self {
            suffixes: AHashMap::new(),
        }
    }

    fn parse_suffix_list(&mut self, suffixes_list: &str) {
        for line in suffixes_list.lines().map(|line| line.to_ascii_lowercase()) {
            if line.starts_with("//") || line.is_empty() {
                continue;
            }

            let mut tlds = vec![line.clone()];
            if !line.is_ascii() {
                tlds.push(idna::domain_to_ascii(&line).unwrap());
            }

            for tld in tlds {
                let fractions: Vec<String> = tld.rsplit('.').map(|s| s.to_string()).collect();
                let mut current_suffix = self
                    .suffixes
                    .entry(fractions.first().unwrap().to_owned())
                    .or_insert_with(Suffix::new);

                for fraction in fractions[1..].iter() {
                    if fraction.starts_with('!') {
                        current_suffix.sub_blacklist.insert(fraction.strip_prefix('!').unwrap().to_string());
                    } else if fraction == "*" {
                        current_suffix.is_wildcard = true;
                    } else {
                        current_suffix = current_suffix.sub_suffixes.entry(fraction.clone()).or_insert_with(Suffix::new);
                    }
                }
            }
        }
    }

    fn parse_domain_parts<'a>(
        &self,
        domain: &'a str,
    ) -> Result<(&'a str, &'a str, &'a str), &'static str> {
        let mut suffix_part = "";
        let mut current_suffixes = &self.suffixes;
        let mut last_dot_index = domain.len();
        let mut in_wildcard_tld = false;
        let mut last_suffix: Option<&Suffix> = None;
    
        while let Some(dot_index) = domain[..last_dot_index].rfind('.') {
            let current_fraction = &domain[dot_index + 1..last_dot_index];
            if current_fraction.is_empty() || dot_index == 0 {
                return Err("Invalid domain detected");
            }
    
            if in_wildcard_tld {
                if last_suffix.unwrap().sub_blacklist.contains(current_fraction) {
                    let leftover_part = &domain[0..dot_index];
    
                    return Ok((suffix_part, current_fraction, leftover_part));
                }
    
                if let Some(current_suffix) = current_suffixes.get(current_fraction) {
                    if !current_suffix.is_wildcard {
                        current_suffixes = &current_suffix.sub_suffixes;
                    }
                    last_suffix.replace(current_suffix);
                    suffix_part = &domain[dot_index + 1..];
                    last_dot_index = dot_index;
                } else {
                    suffix_part = &domain[dot_index + 1..];
                    let leftover_part = &domain[0..dot_index];
                    match leftover_part.rsplit_once('.') {
                        Some((subdomain_part, domain_part)) => {
                            if subdomain_part.ends_with('.') {
                                return Err("Invalid domain detected");
                            }
                            return Ok((suffix_part, domain_part, subdomain_part));
                        }
                        None => {
                            return Ok((suffix_part, leftover_part, ""));
                        }
                    }
                }
            }
            if let Some(current_suffix) = current_suffixes.get(current_fraction) {
                in_wildcard_tld = current_suffix.is_wildcard;
    
                current_suffixes = &current_suffix.sub_suffixes;
                last_suffix.replace(current_suffix);
                suffix_part = &domain[dot_index + 1..];
                last_dot_index = dot_index;
            } else {
                let leftover_part = &domain[0..last_dot_index];
                match leftover_part.rsplit_once('.') {
                    Some((subdomain_part, domain_part)) => {
                        if subdomain_part.ends_with('.') {
                            return Err("Invalid domain detected");
                        }
                        return Ok((suffix_part, domain_part, subdomain_part));
                    }
                    None => {
                        return Ok((suffix_part, leftover_part, ""));
                    }
                };
            }
        }
    
        let current_fraction = &domain[0..last_dot_index];
        if in_wildcard_tld {
            if last_suffix.unwrap().sub_blacklist.contains(current_fraction) {
                Ok((suffix_part, current_fraction, ""))
            } else {
                Ok((domain, "", ""))
            }
        } else if current_suffixes.len() > 0 && current_suffixes.contains_key(current_fraction) {
            Ok((domain, "", ""))
        } else {
            Ok((suffix_part, current_fraction, ""))
        }
    }
    
    fn extract_domain_parts(&self, domain: &str) -> Result<(String, String, String), &'static str> {
        let (suffix_part, domain_part, subdomain_part) = self.parse_domain_parts(domain)?;
        Ok((suffix_part.to_string(), domain_part.to_string(), subdomain_part.to_string()))
    }    
}


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Please provide a domain as an argument.");
        return;
    }

    let mut domain_extractor = DomainExtractor::new();
    let suffix_list = include_str!("public_suffix_list.dat");
    domain_extractor.parse_suffix_list(suffix_list);

    let domain = &args[1];

    let (suffix, domain_part, subdomain) = domain_extractor
        .extract_domain_parts(&domain)
        .expect("Error extracting domain parts");

    println!("{{\"suffix\": \"{}\", \"domain\": \"{}\", \"subdomain\": \"{}\"}}", suffix, domain_part, subdomain);

}
