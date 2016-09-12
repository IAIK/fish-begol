#! /bin/octave -qf

% from http://stackoverflow.com/questions/2219208/aquaterm-titles-and-axis-labels-getting-cut-off
function fixAxes
%---------------------------------------
%// Kludge to fix scaling of all figures
%// until GNU or I can find real fix.
%// Octave3.2.3 computes the scaling wrong
%// for this mac, such that the title 
%// and xlabel are not displayed.
%---------------------------------------
s = get(0,'showhiddenhandles');
set(0,'showhiddenhandles','on');
newpos = [0.13 0.135 0.775 0.75];        %// default is [0.13 0.11 0.775 0.815]
figs = get(0,'children');
if (~isempty(figs))
    for k=1:length(figs)
        cax = get(figs(k),'currentaxes');
        pos = get(cax,'position');
        if ~(pos(1) == newpos(1) && ...
             pos(2) == newpos(2) && ...
             pos(3) == newpos(3) && ...
             pos(4) == newpos(4))
            set(cax,'position',newpos);
            set(0,'currentfigure',figs(k));
            drawnow();
        endif
    endfor
endif
set(0,'showhiddenhandles',s);
%---------------------------------------
endfunction
%---------------------------------------

function create_plot(prefix, n, k, labels, data)
  fig = figure;
  [ax, h1, h2] = plotyy(1:rows(data), data(:, 1:3), 1:rows(data), data(:,4));
  set(h1(1), 'marker', '.','markersize', 8, 'color', 'blue', 'linewidth', 2);
  set(h1(2), 'marker', 'diamond','markersize', 2, 'color', 'red', 'linewidth', 2);
  set(h1(3), 'marker', 'square','markersize', 2, 'color', 'magenta', 'linewidth', 2);
  set(h2, 'marker', '>','markersize', 2, 'color', 'green', 'linewidth', 2);
  set(ax(1), 'ycolor', 'black');
  set(ax(2), 'ycolor', 'black');
  grid on;
  title(strcat("LowMC Timing n=", n, " k=", k, "\n\n", "Parameters [m]-[r]"));
  xlabel(" ");
  set(ax, 'xtick', 1:rows(data));
  set(ax, 'xticklabel', "");  

  xlim([1, rows(data)])
  for i = 1:rows(data)
    text(i, 0, labels(i,:), "rotation", 60, "verticalalignment", "top", "horizontalalignment", "right");
  endfor
  set(get(ax(1),'Ylabel'),'String','Time [ms]');
  set(get(ax(2),'Ylabel'),'String','Signature Size [kB]');
  legend(ax(1), "Instance Gen", "Sign", "Verify");
  fixAxes
  print(fig, strcat(prefix, "-", n, "-", k, ".png"), "-dpng", "-loose");
endfunction

arg_list = argv();

n = arg_list{1};
k = arg_list{2};

data = load(strcat("timings-", n, "-", k, ".mat"));

fiatshamir = transpose(data.fis_sum) / 1000;
bellargw = transpose(data.bg_sum) / 1000;

fs_sum = zeros(rows(data.labels), 4);
bg_sum = zeros(rows(data.labels), 4);

fs_sum(:,1) = sum(fiatshamir(:,1:3), 2);
bg_sum(:,1) = sum(bellargw(:,1:3), 2);
fs_sum(:,2) = sum(fiatshamir(:,4:8), 2);
bg_sum(:,2) = sum(bellargw(:,4:8), 2);
fs_sum(:,3) = sum(fiatshamir(:,9:12), 2);
bg_sum(:,3) = sum(bellargw(:,9:12), 2);
fs_sum(:,4) = sum(fiatshamir(:,13), 2);
bg_sum(:,4) = sum(bellargw(:,13), 2);

create_plot("fis", n, k, data.labels, fs_sum);
create_plot("bg", n, k, data.labels, bg_sum);

