pub mod events;

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    Router,
    response::{
        Html,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt as _, wrappers::BroadcastStream};

use events::WebEvent;

const INDEX_HTML: &str = include_str!("assets/index.html");
const CHART_JS: &str = include_str!("assets/chart.min.js");

pub struct WebServer {
    tx: broadcast::Sender<WebEvent>,
}

impl WebServer {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn sender(&self) -> broadcast::Sender<WebEvent> {
        self.tx.clone()
    }

    /// 在独立 tokio task 中启动 HTTP 服务，立即返回（不阻塞调用者）。
    pub async fn start(self, port: u16) -> anyhow::Result<()> {
        let tx = self.tx;

        let app = Router::new()
            .route("/", get(serve_index))
            .route("/chart.js", get(serve_chart_js))
            .route("/events", get(move || sse_handler(tx.clone())));

        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
            .await
            .map_err(|e| anyhow::anyhow!("Web 服务绑定 0.0.0.0:{port} 失败: {e}"))?;

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("Web 服务异常退出: {e}");
            }
        });

        Ok(())
    }
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_chart_js() -> ([(&'static str, &'static str); 1], &'static str) {
    ([("content-type", "application/javascript")], CHART_JS)
}

async fn sse_handler(
    tx: broadcast::Sender<WebEvent>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().data(json)))
        }
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
