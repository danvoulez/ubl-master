//! Source position tracking for error reporting

use std::fmt;

/// A position in the source text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)
    pub column: usize,
    /// Byte offset in source
    pub offset: usize,
}

impl Position {
    pub fn new(line: usize, column: usize, offset: usize) -> Self {
        Self { line, column, offset }
    }
    
    pub fn start() -> Self {
        Self { line: 1, column: 1, offset: 0 }
    }
    
    /// Advance position by a character
    pub fn advance(&mut self, ch: char) {
        self.offset += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// A span in the source text (start to end position)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: Position,
    pub end: Position,
}

impl Span {
    pub fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }
    
    pub fn single(pos: Position) -> Self {
        Self { start: pos, end: pos }
    }
    
    /// Merge two spans into one that covers both
    pub fn merge(self, other: Span) -> Span {
        Span {
            start: if self.start.offset < other.start.offset { self.start } else { other.start },
            end: if self.end.offset > other.end.offset { self.end } else { other.end },
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.start.line == self.end.line && self.start.column == self.end.column {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}..{}", self.start, self.end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_display() {
        let pos = Position::new(10, 5, 100);
        assert_eq!(format!("{}", pos), "10:5");
    }

    #[test]
    fn test_position_advance() {
        let mut pos = Position::start();
        pos.advance('a');
        assert_eq!(pos.column, 2);
        assert_eq!(pos.line, 1);
        
        pos.advance('\n');
        assert_eq!(pos.line, 2);
        assert_eq!(pos.column, 1);
    }

    #[test]
    fn test_span_display() {
        let span = Span::new(
            Position::new(1, 1, 0),
            Position::new(1, 5, 4)
        );
        assert_eq!(format!("{}", span), "1:1..1:5");
    }

    #[test]
    fn test_span_single() {
        let pos = Position::new(1, 1, 0);
        let span = Span::single(pos);
        assert_eq!(format!("{}", span), "1:1");
    }
}

