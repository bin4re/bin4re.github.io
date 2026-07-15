/* jshint asi:true */

/**
 * [fixSidebar description]
 * 滚轮滚到一定位置时，将 sidebar-wrap 添加 fixed 样式
 * 反之，取消样式
 */
(function() {
    if (window.innerWidth > 770) {

        var sidebarWrap = document.querySelector('.right>.wrap')

        //fix 之后百分比宽度会失效，这里用js赋予宽度
        sidebarWrap.style.width = sidebarWrap.offsetWidth + "px"
        window.onscroll = function() {

            // 页面顶部滚进去的距离
            var scrollTop = Math.max(document.documentElement.scrollTop, document.body.scrollTop)


            // 页面底部滚进去的距离
            var htmlHeight = Math.max(document.body.clientHeight, document.documentElement.clientHeight)
                // console.log(htmlHeight);
            var scrollBottom = htmlHeight - window.innerHeight - scrollTop

            if (scrollTop < 53) {
                sidebarWrap.classList.remove('fixed')
                sidebarWrap.classList.remove('scroll-bottom')
            } else if (scrollBottom >= (190 - 38)) {
                sidebarWrap.classList.remove('scroll-bottom')
                sidebarWrap.classList.add('fixed')
            } else if (isMaxHeight()) { //content 达到maxHeight
                sidebarWrap.classList.remove('fixed')
                sidebarWrap.classList.add('scroll-bottom')
            }
        }
        setContentMaxHeightInPC() //设置目录最大高度(PC端)
    }
    moveTOC() //将Content内容转移
}());

/**
 * 设置目录最大高度
 */
function setContentMaxHeightInPC() {
    var windowHeight = window.innerHeight
    var contentUl = document.querySelector('.content-ul')
    var contentMaxHeight = windowHeight - 77 - 60
    contentUl.style.maxHeight = contentMaxHeight + 'px'
}

/**
 * 达到最大高度
 * @return {Boolean} [description]
 */
function isMaxHeight() {
    var windowHeight = window.innerHeight
    var contentUl = document.querySelector('.content-ul')
    var contentMaxHeight = windowHeight - 77 - 60
    var contentHeight = contentUl.offsetHeight
    return contentMaxHeight === contentHeight
        // console.log(contentMaxHeight);
        // console.log(contentHeight);
}


//-------------mobile--------------
/**
 * 屏幕宽度小于770px时，点击锚点按钮，弹出目录框
 * @param  {[type]} function( [description]
 * @return {[type]}           [description]
 */
(function() {
    if (window.innerWidth <= 770) {
        var anchorBtn = document.querySelector('.anchor')
        var rightDiv = document.querySelector('.right')

        /**
         * 监听锚点按钮
         */
        anchorBtn.onclick = function(e) {
            e.stopPropagation()
            rightDiv.classList.add('right-show')
            anchorBtn.classList.add('anchor-hide')
        }

        //监听body，点击body，隐藏Content
        document.querySelector('body').addEventListener('click', function() {
            rightDiv.classList.remove('right-show')
            anchorBtn.classList.remove('anchor-hide')
        })

        ancherPostion(anchorBtn, rightDiv) //目录锚的位置固定
        setContentMaxHeight() //设置目录最大高度
    }
}());

/**
 * 目录锚的位置固定
 */
function ancherPostion(anchorBtn, rightDiv) {
    window.addEventListener('scroll', function() {
        // console.log('scroll');
        var top = anchorBtn.getBoundingClientRect().top
            // console.log(top);
        var scrollTop = Math.max(document.documentElement.scrollTop, document.body.scrollTop)
        if (scrollTop > 50) {
            anchorBtn.style.top = '20px'
            rightDiv.style.top = '20px'
        } else {
            anchorBtn.style.top = '76px'
            rightDiv.style.top = '76px'
        }
    })
}

/**
 * 设置目录最大高度
 */
function setContentMaxHeight() {
    var windowHeight = window.innerHeight
    var contentUl = document.querySelector('.content-ul')
    var contentMaxHeight = windowHeight - 180
    contentUl.style.maxHeight = contentMaxHeight + 'px'
}

//-------------post Content----------------------
//将Content内容转移
function moveTOC() {
    var page = document.querySelector('.page[post]')
    if (!page) return //非文章页（archives/category/tags 等列表页）不处理

    var contentUl = document.querySelector('#content-side')
    if (!contentUl) return

    var container = document.querySelector('article')
    var headings = container ? container.querySelectorAll('h1, h2, h3, h4, h5, h6') : []

    if (headings.length === 0) {
        //无标题：隐藏右侧目录栏，正文居中限宽（由 .no-toc 样式控制）
        page.classList.add('no-toc')
        return
    }

    //为缺少 id 的标题补上 id（Kramdown 通常已自动生成）
    for (var i = 0; i < headings.length; i++) {
        if (!headings[i].id) {
            headings[i].id = 'toc-' + (i + 1)
        }
    }

    var html = buildTOC(headings)
    contentUl.insertAdjacentHTML('afterbegin', html)

    //添加 data-scroll，为了平滑滚动
    var aTags = document.querySelectorAll('#content-side a')
    for (var i = 0; i < aTags.length; i++) {
        if (!aTags[i].hasAttribute('data-scroll')) {
            aTags[i].setAttribute('data-scroll', '')
        }
    }
}

//根据标题级别构建嵌套 <ul><li> 目录结构
function buildTOC(headings) {
    var levels = []
    for (var i = 0; i < headings.length; i++) {
        levels.push(parseInt(headings[i].tagName.charAt(1), 10))
    }
    var minLevel = Math.min.apply(null, levels)
    var prevLevel = minLevel
    var html = ''

    for (var i = 0; i < headings.length; i++) {
        var lvl = levels[i]
        var id = headings[i].id
        var text = escapeHTML((headings[i].textContent || '').trim())

        if (i === 0) {
            html += '<li><a href="#' + id + '" data-scroll>' + text + '</a>'
        } else if (lvl === prevLevel) {
            html += '</li><li><a href="#' + id + '" data-scroll>' + text + '</a>'
        } else if (lvl > prevLevel) {
            for (var k = prevLevel; k < lvl; k++) html += '<ul><li>'
            html += '<a href="#' + id + '" data-scroll>' + text + '</a>'
        } else {
            html += '</li>'
            for (var k = lvl; k < prevLevel; k++) html += '</ul></li>'
            html += '<li><a href="#' + id + '" data-scroll>' + text + '</a>'
        }
        prevLevel = lvl
    }

    html += '</li>'
    for (var k = minLevel; k < prevLevel; k++) html += '</ul></li>'
    return html
}

function escapeHTML(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
}
