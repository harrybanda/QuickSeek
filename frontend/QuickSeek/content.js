var open = false;
var transData = [];
var sentiment = {};

var toHHMMSS = secs => {
  var sec_num = parseInt(secs, 10);
  var hours = Math.floor(sec_num / 3600) % 24;
  var minutes = Math.floor(sec_num / 60) % 60;
  var seconds = sec_num % 60;
  return [hours, minutes, seconds]
    .map(v => (v < 10 ? "0" + v : v))
    .filter((v, i) => v !== "00" || i > 0)
    .join(":");
};

const callAPI = async id => {
  showStatus("> Getting video...");
  await fetch(
    "https://x6687eomak.execute-api.us-east-1.amazonaws.com/Prod/download-to-s3/" +
      id
  );

  showStatus("> Started transcription.");
  await fetch(
    "https://x6687eomak.execute-api.us-east-1.amazonaws.com/Prod/transcribe-audio/" +
      id
  );

  showStatus("> Transcribing audio, this may take a while.");
  while (true) {
    const response = await fetch(
      "https://x6687eomak.execute-api.us-east-1.amazonaws.com/Prod/check-status/" +
        id
    );
    const result = await response.json();
    if (result.status !== "IN_PROGRESS") break;
    await new Promise(resolve => {
      setTimeout(resolve, 10000);
    });
  }

  showStatus("> Complete!");
  const response2 = await fetch(
    "https://x6687eomak.execute-api.us-east-1.amazonaws.com/Prod/get-transcripts/" +
      id
  );
  const result2 = await response2.json();
  transData = organizeData(result2.json);
  sentiment = result2.sentiment
  $("#status").remove();
  appendSearch();
};

const organizeData = results => {
  data = [];
  filtered = results.filter(function(obj) {
    return obj.type !== "punctuation";
  });
  filtered.forEach(function(obj) {
    data.push({
      time: obj.start_time,
      word: obj.alternatives[0].content
    });
  });
  return data;
};

const appendSearch = () => {
  $.get(chrome.extension.getURL("search.html"), function(data) {
    $("#body")
      .empty()
      .append(data);
  });
};

const appendChart = () => {
  $(document).on("click", "#btnInsights", function() {
    $("#msgMatch").remove();
    $("#insights-div").remove();
    $(".btnSeek").remove();
    $("#body").append(
      "<div id='insights-div'>" +
        "<h5 class='subtitle is-5 has-text-grey'>Sentiment Analysis</h5>" +
        "<canvas id='myChart'></canvas>" +
      "</div>" 
    );
    loadChart();
  });
};

const removePopup = () => {
  $(document).on("click", ".delete", function() {
    $("#popup").remove();
    open = false;
  });
};

const analyzeVideo = id => {
  $(document).on("click", "#analyze", function() {
    $("#body")
      .empty()
      .append("<div class='loading_qs'></div>");
    callAPI(id);
  });
};

const checkMatch = message => {
  $(".matches")
    .empty()
    .append(
      "<h5 id='msgMatch' class='subtitle is-5 has-text-grey'>" +
        message +
        "</h5>"
    );
};

const showStatus = message => {
  $("#body").append(
    "<div id='status'><h5 class='subtitle is-5 has-text-grey center'>" +
      message +
      "</h5></div>"
  );
};

const search = () => {
  $(document).on("keyup", "#search", function() {
    input = this.value;
  });

  $(document).on("click", "#btnSearch", function() {
    $("#insights-div").remove();
    if (input == "[object HTMLCollection]") {
      input = "";
    }

    data = transData
      .filter(x => x.word.toLowerCase() === input.toLowerCase())
      .map(x => x.time);

    if (Object.keys(data).length == 0 && input != "") {
      $(".buttons").empty();
      checkMatch("No matches found");
    } else if (Object.keys(data).length != 0) {
      if (Object.keys(data).length == 1) {
        checkMatch("1 match found");
      } else {
        checkMatch(data.length + " matches found");
      }
      $(".buttons").empty();
      data.forEach(function(seconds) {
        $(".buttons").append(
          "<span class='button is-primary is-medium btnSeek' value='" +
            seconds +
            "'>" +
            toHHMMSS(seconds) +
            "</span>"
        );
      });
    }
  });
};

const seek = () => {
  $(document).on("click", ".btnSeek", function() {
    time = $(this).attr("value");
    video = document.getElementsByClassName("video-stream html5-main-video")[0];
    video.currentTime = time;
  });
};

const loadChart = () => {
  var ctx = document.getElementById("myChart").getContext("2d");

  positive = Math.round(sentiment.SentimentScore.Positive * 100) / 100;
  neutral = Math.round(sentiment.SentimentScore.Neutral * 100) / 100;
  negative = Math.round(sentiment.SentimentScore.Negative * 100) / 100;

  data = {
    datasets: [
      {
        data: [positive, neutral, negative],
        backgroundColor: [
          "rgba(35, 209, 96, 1)",
          "rgba(50, 115, 220, 1)",
          "rgba(255, 59, 96, 1)"
        ]
      }
    ],

    labels: ["Positive", "Neutral", "Negative"]
  };

  var myPieChart = new Chart(ctx, {
    type: "pie",
    data: data,
    options: {}
  });
};

chrome.runtime.onMessage.addListener(function(request) {
  if (request.todo == "openDialog" && open == false) {
    $.get(chrome.extension.getURL("popup.html"), function(data) {
      $(data).appendTo("body");
    });
    analyzeVideo(request.vid);
    appendChart();
    search();
    seek();
    removePopup();
    open = true;
  }
});
