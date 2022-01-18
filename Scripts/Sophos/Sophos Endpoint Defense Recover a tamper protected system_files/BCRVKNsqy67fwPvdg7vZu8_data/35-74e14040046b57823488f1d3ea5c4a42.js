(window.webpackJsonp=window.webpackJsonp||[]).push([[35],{1649:
/*!******************************************************************************!*\
  !*** ../player/components/media/video/hlsJsVideo/hlsJsVideo.tsx + 1 modules ***!
  \******************************************************************************/
/*! exports provided: default */
/*! all exports used */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/media/video/Video.tsx */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/customHooks/useMux.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/customHooks/useStoreSelector.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/state/analytics/actions.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/state/config/types.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/state/playback/actions.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../node_modules/hls.js/dist/hls.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ../node_modules/react-redux/es/index.js */
/*! ModuleConcatenation bailout: Cannot concat with ../node_modules/react/index.js (<- Module is not an ECMAScript module) */function(e,t,n){"use strict";n.r(t);var y=n(366),E=n.n(y),k=n(369),c=n(849),g=n.n(c),w=n(872),_=n(851),T=n(368),C=n(379),A=n(402),S=n(602);t.default=function(){var u=Object(k.c)(),e=Object(y.useState)(!0),c=e[0],t=e[1],n=Object(T.c)("canPlay"),r=Object(T.c)("quality"),a=Object(T.c)("audioTrack"),o=Object(T.b)("preload"),i=Object(k.d)(function(e){e=e.ui.splashScreen;return"none"!==o||!e}),f=Object(k.d)(function(e){var t=e.playback.currentChapter,e=e.config.chapters;return i?e[t].sources.hls:null}),b=Object(k.d)(function(e){var t=e.playback.paused,n=e.config,e=n.firstFrame,n=n.playlistStartOpen;return"auto"!==o&&c&&(!t||e||n)}),l=Object(y.useRef)(null),s=Object(y.useRef)(),d=Object(y.useRef)(r),e=Object(y.useState)(!1),j=e[0],O=e[1],e=Object(y.useState)(!1),v=e[0],p=e[1],e=Object(y.useState)(!1),m=e[0],h=e[1];return Object(y.useEffect)(function(){s.current=new g.a({autoStartLoad:"auto"===o,capLevelToPlayerSize:!0,startLevel:"auto"===d.current?-1:void 0,maxBufferSize:1e6});function n(){return p(!0)}function c(e,t){t=t.audioTracks,O(!0),t=t.map(function(e){return e.name}),u(Object(C.v)(t))}function r(){return h(!0)}return s.current.on(g.a.Events.MEDIA_ATTACHED,n),s.current.on(g.a.Events.MANIFEST_PARSED,c),s.current.on(g.a.Events.AUDIO_TRACKS_UPDATED,r),s.current.attachMedia(l.current),u(Object(A.p)("hls")),function(){var e,t;O(!1),p(!1),h(!1),null!==(e=s.current)&&void 0!==e&&e.off(g.a.Events.MEDIA_ATTACHED,n),null!==(e=s.current)&&void 0!==e&&e.off(g.a.Events.MANIFEST_PARSED,c),null!==(e=s.current)&&void 0!==e&&e.off(g.a.Events.AUDIO_TRACKS_UPDATED,r);try{null!==(t=s.current)&&void 0!==t&&t.destroy()}catch(e){if(!(e instanceof TypeError&&"listener must be a function"===e.message))throw e}u(Object(A.j)())}},[u,o]),Object(y.useEffect)(function(){var e,t,n,c;v&&f&&(t=f.find(function(e){return"auto"===e.profile})||f[0],c=(n=f.map(function(e){return e.profile})).includes(d.current)?d.current:t.profile,null!==(e=s.current)&&void 0!==e&&e.loadSource(t.url),u(Object(C.w)(n)),u(Object(C.D)(c)))},[v,f,u]),Object(y.useEffect)(function(){var t,e;j&&s.current&&(e=s.current.levels.map(function(e){return e.height}),s.current.nextLevel=(e=e,"auto"===(t=r)?-1:e.map(function(t){return S.d.find(function(e){return t<=parseInt(e)})}).findIndex(function(e){return e===t})))},[j,r]),Object(y.useEffect)(function(){m&&s.current&&(s.current.audioTrack=a)},[m,a]),Object(y.useEffect)(function(){var e;b&&j&&(null!==(e=s.current)&&void 0!==e&&e.startLoad(),t(!1))},[b,j]),Object(y.useEffect)(function(){n&&l.current&&0===l.current.currentTime&&(l.current.currentTime=l.current.currentTime)},[l,n]),Object(_.a)(l,s),E.a.createElement(w.a,{ref:l})}},850:
/*!***************************************************!*\
  !*** ../player/components/media/video/Video.scss ***!
  \***************************************************/
/*! no static exports found */
/*! exports used: hideCursor, hideVideo, video */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */function(e,t,n){e.exports={video:"_1l-KU",hideCursor:"_3OgU3",hideVideo:"_3-9KU"}},851:
/*!********************************************************!*\
  !*** ../player/components/utils/customHooks/useMux.ts ***!
  \********************************************************/
/*! exports provided: default */
/*! exports used: default */function(e,t,n){"use strict";var i=n(/*! react */366),f=n(/*! react-redux */369),b=n(/*! ../../utils/customHooks/useStoreSelector */368),c=n(/*! mux-embed */965),l=n.n(c),c=n(/*! hls.js */849),s=n.n(c);t.a=function(t,n){var c=Object(b.a)("visitorId"),r=Object(b.b)("playerUuid"),u=Object(b.b)("accountId"),a=Object(f.d)(function(e){return e.config.chapters[e.playback.currentChapter].videoId}),o=Object(f.d)(function(e){var t=e.config,e=t.onComplete,t=t.chapterLoop;return"loop"===e||!!t});Object(i.useEffect)(function(){var e=!o&&Math.floor(100*Math.random())<=15;t.current&&(void 0===n||n.current)&&e&&l.a.monitor("."+t.current.classList[0],{debug:!1,disableCookies:!0,hlsjs:n?n.current:void 0,Hls:n?s.a:void 0,data:{env_key:"vfhbo3jsnvrutdkuee1akd0lj",player_name:"Pomo Player",player_init_time:window.__startTime,player_version:"92393973d557de761aa79bfe623d465020076a72",video_id:a,video_series:r,video_title:a,video_stream_type:"on-demand",viewer_user_id:c,page_type:window.location!==window.parent.location?"iframe":"watchpage",sub_property_id:u}})},[t,u,a,r,n,c,o])}},872:
/*!**************************************************************!*\
  !*** ../player/components/media/video/Video.tsx + 3 modules ***!
  \**************************************************************/
/*! exports provided: default */
/*! exports used: default */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/autoplayPermission.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/customHooks/usePostRoll.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/customHooks/usePrevious.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/customHooks/useShouldRenderCaptions.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/customHooks/useStoreSelector.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/utils/userBrowserChecker/UserBrowserChecker.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/state/playback/actions.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/state/ui/actions.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../player/state/ui/thunks.ts */
/*! ModuleConcatenation bailout: Cannot concat with ../node_modules/classnames/index.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ../player/components/media/video/Video.scss (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ../node_modules/react-redux/es/index.js */
/*! ModuleConcatenation bailout: Cannot concat with ../node_modules/react/index.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ../player/node_modules/unfetch/dist/unfetch.mjs */function(e,t,n){"use strict";var J=n(366),V=n.n(J),W=n(369),c=n(371),G=n.n(c),Q=n(609),X=n(368),Y=n(401),Z=n(379),$=n(372),ee=n(672),o=n(132);function i(e){return"track-"+e.id}function te(){var r=Object(W.d)(function(e){var t=e.playback.currentChapter;return e.config.chapters[t].captions}),u=Object(W.d)(function(e){e=e.config.userBrowser;return Object(Y.d)(e)}),e=Object(J.useState)({}),t=e[0],a=e[1];return Object(J.useEffect)(function(){for(var c={},e=0,t=r;e<t.length;e++)!function(t){u?Object(o.a)(t.vttUrl,{method:"GET"}).then(function(e){return e.blob()}).then(function(e){c[i(t)]=URL.createObjectURL(e)}):c[i(t)]=t.vttUrl}(t[e]);return a(c),function(){if(u)for(var e=0,t=r;e<t.length;e++){var n=t[e];URL.revokeObjectURL(c[i(n)]),a({})}}},[r,u]),V.a.createElement(V.a.Fragment,null,r.map(function(e){return V.a.createElement("track",{id:i(e),key:e.id,kind:"captions",label:e.name,srcLang:e.language,src:t[i(e)]})}))}var f=n(670);function ne(c){var r=Object(W.c)(),u=Object(X.c)("canPlay"),a=Object(X.c)("caption"),o=Object(f.a)();Object(J.useEffect)(function(){var e;if(u){var n=null===(e=c.current)||void 0===e?void 0:e.textTracks;if(n)for(var t=0;t<n.length;t++)!function(e){var t=n[e];o&&null!==a&&t.id===i(a)?(t.oncuechange=function(){var e=Array.from(t.activeCues);r(Object(Z.b)(e))},t.mode="hidden"):"disabled"!==t.mode&&(t.mode="disabled")}(t)}},[a,o,u,r,c])}var ce=function(){for(var e=0,t=0,n=arguments.length;t<n;t++)e+=arguments[t].length;for(var c=Array(e),r=0,t=0;t<n;t++)for(var u=arguments[t],a=0,o=u.length;a<o;a++,r++)c[r]=u[a];return c};var re=n(850),ue=n(434),ae=n(510);t.a=Object(J.forwardRef)(function(t,e){var a=Object(W.c)(),n=Object(X.b)("pauseDisabled"),c=Object(X.b)("chapterLoop"),r=Object(X.b)("redirectWholePage"),u=Object(X.b)("redirectUrl"),o=Object(X.b)("disableRedirect"),i=Object(X.b)("onComplete"),f=Object(X.b)("background"),b=Object(X.b)("userBrowser"),l=Object(X.b)("disableCtas"),s=Object(X.b)("preload"),d=Object(X.b)("autoplay"),j=Object(X.c)("currentChapter"),O=Object(X.c)("paused"),v=Object(X.c)("mute"),p=Object(X.c)("seekTo"),m=Object(X.c)("seekFrom"),h=Object(X.c)("speed"),y=Object(X.c)("volume"),E=Object(X.c)("canPlay"),k=Object(X.c)("time"),g=Object(X.d)("splashScreen"),w=Object(X.d)("userActive"),_=Object(ue.a)(),T=Object(J.useState)(!0),C=T[0],A=T[1],S=Object(W.d)(function(e){var t=e.playback.currentChapter;return e.config.chapters[t].name}),D=Object(W.d)(function(e){return e.playback.currentChapter===e.config.chapters.length-1}),T=Object(W.d)(function(e){var t=e.ui,e=t.userActive,t=t.controlsLocked;return!e&&!t}),P=Object(W.d)(function(e){var t=e.ui.playerDimensions;return e.playback.duration/t.width}),R=Object(W.d)(function(e){return!(null===(e=e.ui.eventState[null==_?void 0:_.id])||void 0===e||!e.playDisabled)}),L=Object(W.d)(function(e){return null===(e=e.ui.eventState[null==_?void 0:_.id])||void 0===e?void 0:e.dismissed}),U=Object(ae.a)(L),I=_&&"vyFreePostRoll"===_.eventType,x=Object(J.useRef)(null),F=Object(J.useRef)(O),M=Object(J.useRef)(),H=Object(J.useRef)();Object(J.useImperativeHandle)(e,function(){return x.current});var K={start:function(){x.current&&(Math.abs(x.current.currentTime-k)>=P&&a(Object(Z.H)(x.current.currentTime)),M.current=window.requestAnimationFrame(function(){var e;return null===(e=H.current)||void 0===e?void 0:e.start()}))},stop:function(){null!=M.current&&cancelAnimationFrame(M.current),M.current=void 0}};Object(J.useEffect)(function(){H.current=K},[K]);var N=Object(J.useCallback)(function(){var e;E&&(O?null!==(e=x.current)&&void 0!==e&&e.pause():(e=null===(e=x.current)||void 0===e?void 0:e.play())instanceof Promise?e.catch(function(){!F.current&&x.current&&x.current.paused&&!x.current.muted&&2!==d?a(Object(Z.l)()):2===d&&C&&(a(Object(Z.j)()),a(Object($.E)()))}).finally(function(){A(!1)}):A(!1))},[E,O,d,C,a]);Object(J.useEffect)(function(){0<d&&!g&&a(Object(Z.k)())},[d,g,a]),Object(J.useEffect)(function(){N()},[N]),Object(J.useEffect)(function(){F.current=O},[O]),Object(J.useEffect)(function(){x.current&&(x.current.muted=v)},[v]),Object(J.useEffect)(function(){var e;null!==(e=x.current)&&void 0!==e&&e.paused&&!O&&v&&N()},[v,O,N]),Object(J.useEffect)(function(){E&&0<=p&&x.current&&p<=x.current.duration&&(Number.isFinite(p)&&(x.current.currentTime=p,a(Object(Z.H)(p))),a(Object(Z.r)()))},[E,p,a]),Object(J.useEffect)(function(){x.current&&(x.current.volume=y)},[y]),Object(J.useEffect)(function(){E&&x.current&&(x.current.playbackRate=h)},[E,h]),Object(J.useEffect)(function(){return function(){a(Object(Z.y)(!1))}},[a]);var B,q,z=Object(J.useCallback)(function(){if(c)return a(Object(Z.h)()),a(Object(Z.a)()),void N();if(!D)return a(Object(Z.t)(j+1)),void a(Object(Z.a)());switch(a(Object(Z.m)()),a(Object(ee.b)(0)),i){case"redirect_url":o?(a(Object($.E)()),a(Object($.s)(!1)),a(Object(Z.o)()),a(Object(Z.a)())):(r?window.top:window).location.replace(u);break;case"final_frame":a(Object(Z.j)()),a(Object($.s)(!1));break;case"loop":a(Object(Z.i)()),a(Object(Z.a)()),N();break;case"splash_screen":a(Object($.E)()),a(Object($.s)(!1)),a(Object(Z.o)()),a(Object(Z.a)())}},[c,j,a,D,i,u,r,o,N]);Object(J.useEffect)(function(){R||!1!==U||!L||I||z()},[z,R,L,U,I]),Object(J.useEffect)(function(){a(Object(ee.c)(j))},[j,a]),ne(x),B=Object(X.b)("pauseDisabled"),q=Object(X.b)("hiddenControls"),Object(J.useEffect)(function(){if(navigator.mediaSession){var e=B||q?[]:[["play",null],["pause",null],["stop",null],["seekbackward",null],["seekforward",null],["seekto",null]];B&&(e=ce(e,[["play",function(){}],["stop",function(){}],["pause",function(){}]]));for(var t=0,n=e=q?ce(e,[["seekbackward",function(){}],["seekforward",function(){}],["seekto",function(){}]]):e;t<n.length;t++){var c=n[t],r=c[0],c=c[1];try{navigator.mediaSession.setActionHandler(r,c)}catch(e){}}}},[B,q]);e=G()(re.video,((e={})[re.hideCursor]=T,e[re.hideVideo]=g,e));return V.a.createElement("video",{"aria-label":S,preload:s,crossOrigin:"anonymous",ref:x,className:e,style:{backgroundColor:f},playsInline:!0,onDurationChange:function(){x.current&&isFinite(x.current.duration)&&a(Object(Z.e)(x.current.duration))},onTimeUpdate:function(){-1===p&&x.current&&a(Object(Z.H)(x.current.currentTime))},onContextMenu:function(e){e.preventDefault()},onClick:function(){var e;(Object(Y.h)(b)||Object(Y.f)(b))&&Object(Q.a)(),n||a((O?Object(Z.k):Object(Z.j))()),null!==(e=x.current)&&void 0!==e&&e.focus()},onEnded:function(){K.stop(),!l&&_||z()},onPause:function(){var e;n?null!==(e=x.current)&&void 0!==e&&e.play():K.stop()},onPlay:function(){O||a(Object(Z.k)()),K.start()},onCanPlayThrough:function(){a(Object(Z.x)(!1))},onCanPlay:function(){a(Object(Z.y)(!0))},onSeeked:function(){m!==p&&a(Object(ee.b)(k))},onProgress:function(){if(x.current)for(var e=x.current,t=e.buffered,n=e.currentTime,c=e.duration,r=0;r<t.length;r++)if(t.start(t.length-1-r)<n){var u=t.end(t.length-1-r)/c;a(Object(Z.A)(u));break}},onWaiting:function(){a(Object(Z.x)(!0))},onPlaying:function(){var e;a(Object(Z.x)(!1)),null!==(e=t.onPlaying)&&void 0!==e&&e.call(t)},onLoadedData:function(){var e;null!==(e=t.onLoadedData)&&void 0!==e&&e.call(t)},"data-testid":"video",tabIndex:w?-1:0},V.a.createElement(te,null))})}}]);