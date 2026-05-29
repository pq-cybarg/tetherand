//! ratatui dashboard for `tetherand tui`.
//!
//! Lays out a 4-panel terminal UI:
//!   ┌─ TRANSPORTS ────────┬─ TRAFFIC ────────┐
//!   │ usb-adb   ●         │   ▂▃▅▇█▇▅▃▂▂     │
//!   │ usb-aoa   ○         │                  │
//!   │ bt        ○         │   rx 1.2 MB      │
//!   │ tcp       ●         │   tx 480 KB      │
//!   ├─ DEVICES ───────────┼─ EVENTS ─────────┤
//!   │ Seeker abc123 (usb) │ 12:00 connected  │
//!   │                     │ 12:01 reverse OK │
//!   └─────────────────────┴──────────────────┘
//!
//! q quits. The TUI is read-only — it observes the relay's transport
//! state via a shared `DashboardState` struct; no control from the TUI.

use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};
use ratatui::Terminal;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Snapshot of relay state. Shared between the relay loop and the TUI.
#[derive(Clone, Default)]
pub struct DashboardState {
    pub transports: Vec<TransportRow>,
    pub devices:    Vec<DeviceRow>,
    pub events:     VecDeque<String>,
    pub rx_bytes:   u64,
    pub tx_bytes:   u64,
    pub rx_history: VecDeque<u64>,
}

#[derive(Clone)]
pub struct TransportRow { pub name: String, pub connected: bool, pub note: String }

#[derive(Clone)]
pub struct DeviceRow { pub serial: String, pub model: String, pub transport: String }

/// Run the dashboard. Returns Ok(()) when the user presses q.
pub fn run(state: Arc<Mutex<DashboardState>>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = loop_tui(&mut terminal, state);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn loop_tui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: Arc<Mutex<DashboardState>>,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let area = f.area();
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(area);
            let left = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(cols[0]);
            let right = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(cols[1]);

            let st = state.lock().unwrap().clone();

            // Transports.
            let mut lines: Vec<Line> = vec![];
            for t in &st.transports {
                let dot = if t.connected { Span::styled("●", Style::default().fg(Color::Green)) }
                          else            { Span::styled("○", Style::default().fg(Color::DarkGray)) };
                lines.push(Line::from(vec![
                    Span::styled(format!("{:<9}", t.name), Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" "), dot, Span::raw(" "), Span::raw(t.note.clone()),
                ]));
            }
            let transports = Paragraph::new(lines).block(Block::default().title("TRANSPORTS").borders(Borders::ALL));
            f.render_widget(transports, left[0]);

            // Devices.
            let dev_lines: Vec<Line> = st.devices.iter()
                .map(|d| Line::from(format!("{} {}  ({})", d.model, d.serial, d.transport)))
                .collect();
            let devices = Paragraph::new(dev_lines).block(Block::default().title("DEVICES").borders(Borders::ALL));
            f.render_widget(devices, left[1]);

            // Traffic sparkline + counters.
            let hist: Vec<u64> = st.rx_history.iter().cloned().collect();
            let spark = Sparkline::default()
                .block(Block::default().title("TRAFFIC (rx)").borders(Borders::ALL))
                .data(&hist);
            f.render_widget(spark, right[0]);

            let stats = Paragraph::new(vec![
                Line::from(format!("rx {}", human(st.rx_bytes))),
                Line::from(format!("tx {}", human(st.tx_bytes))),
            ]).block(Block::default().title("EVENTS").borders(Borders::ALL));
            f.render_widget(stats, right[1]);
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc) { return Ok(()); }
            }
        }
    }
}

fn human(n: u64) -> String {
    const KB: u64 = 1024;
    if n >= KB * KB * KB { format!("{:.1} GB", n as f64 / (KB * KB * KB) as f64) }
    else if n >= KB * KB { format!("{:.1} MB", n as f64 / (KB * KB) as f64) }
    else if n >= KB      { format!("{:.1} KB", n as f64 / KB as f64) }
    else                 { format!("{} B",     n) }
}
