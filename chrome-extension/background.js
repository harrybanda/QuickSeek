function getVideoId(url) {
  var regExp = /^.*(youtu\.be\/|v\/|u\/\w\/|embed\/|watch\?v=|\&v=)([^#\&\?]*).*/;
  var match = url.match(regExp);
  if (match && match[2].length == 11) {
    return match[2];
  } else {
    alert("Invalid URL");
    return "error";
  }
}

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (tab.url.indexOf("https://www.youtube.com/watch") == 0) {
    chrome.pageAction.show(tabId);
  } else {
    chrome.pageAction.hide(tabId);
  }
});

chrome.pageAction.onClicked.addListener(function(tab) {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    var url = tabs[0].url;
    var id = getVideoId(url);

    if (id != "error") {
      chrome.tabs.sendMessage(tabs[0].id, { todo: "openDialog", vid: id });
    }
  });
});
