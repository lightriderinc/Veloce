// Minimal JSON writer used for qSearch outputs (std-only build).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub enum J {
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn s(v: &str) -> J {
        J::Str(v.to_string())
    }

    // Pretty printer: client-facing report files are meant to be read.
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out.push('\n');
        out
    }

    fn write_pretty(&self, out: &mut String, level: usize) {
        let pad = "  ".repeat(level + 1);
        let close = "  ".repeat(level);
        match self {
            J::Arr(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&pad);
                    item.write_pretty(out, level + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&close);
                out.push(']');
            }
            J::Obj(members) if !members.is_empty() => {
                out.push_str("{\n");
                for (i, (k, v)) in members.iter().enumerate() {
                    out.push_str(&pad);
                    out.push_str(&esc(k));
                    out.push_str(": ");
                    v.write_pretty(out, level + 1);
                    if i + 1 < members.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&close);
                out.push('}');
            }
            other => out.push_str(&other.dump()),
        }
    }

    pub fn dump(&self) -> String {
        match self {
            J::Bool(b) => b.to_string(),
            J::Num(n) => {
                if *n == n.trunc() && n.abs() < 9e15 {
                    format!("{}", *n as i64)
                } else {
                    format!("{}", n)
                }
            }
            J::Str(s) => esc(s),
            J::Arr(items) => {
                let inner: Vec<String> =
                    items.iter().map(|i| i.dump()).collect();
                format!("[{}]", inner.join(","))
            }
            J::Obj(members) => {
                let inner: Vec<String> = members
                    .iter()
                    .map(|(k, v)| format!("{}:{}", esc(k), v.dump()))
                    .collect();
                format!("{{{}}}", inner.join(","))
            }
        }
    }
}

#[macro_export]
macro_rules! jobj {
    ($($k:expr => $v:expr),* $(,)?) => {
        $crate::json::J::Obj(vec![$(($k.to_string(), $v)),*])
    };
}
