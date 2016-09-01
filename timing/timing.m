#! /bin/octave -qf

function create_plot(prefix, args, data)
  fig = figure('papersize', [1000, 1000]);
  [ax, h1, h2] = plotyy(1:rows(data), data(:, 1:3), 1:rows(data), data(:,4));
  set(h1(1), 'marker', '.','markersize', 8, 'color', 'blue', 'linewidth', 2);
  set(h1(2), 'marker', 'diamond','markersize', 2, 'color', 'red', 'linewidth', 2);
  set(h1(3), 'marker', 'square','markersize', 2, 'color', 'magenta', 'linewidth', 2);
  set(h2, 'marker', '>','markersize', 2, 'color', 'green', 'linewidth', 2);
  set(ax(1), 'ycolor', 'black');
  set(ax(2), 'ycolor', 'black');
  grid on;
  title(strcat("LowMC Timing n=", args{1}, " k=", args{2}, "\n\n", "Parameters [m]-[r]"));
  xlabel(" ");
  set(ax, 'xtick', 1:rows(data));
  set(ax, 'xticklabel', "");  

  xlim([1, rows(data)])
  for i = 1:rows(data)
    text(i, 0, args{i + 2}, "rotation", 60, "verticalalignment", "top", "horizontalalignment", "right");
  endfor
  set(get(ax(1),'Ylabel'),'String','Time [ms]');
  set(get(ax(2),'Ylabel'),'String','Signature Size [kB]');
  legend(ax(1), "Instance Gen", "Sign", "Verify");
  set (gca, "position", [0.1 0.1 0.8 0.8]) 
  print(fig, strcat(prefix, "-", args{1}, "-", args{2}, ".jpg"), "-djpg", "-loose");
endfunction

arg_list = argv();

fiatshamir = zeros(nargin - 2, 14);
bellargw   = zeros(nargin - 2, 14);

for i = 3:nargin
  data = csvread(arg_list{i}) / 1000;
  numr = rows(data)/2;
  fiatshamir(i - 2, :) = sum(data(1:numr,:),1)/numr;
  bellargw(i - 2, :) = sum(data(numr+1:rows(data) ,:),1)/numr;
endfor

fs_sum = zeros(nargin - 2, 4);
bg_sum = zeros(nargin - 2, 4);

fs_sum(:,1) = sum(fiatshamir(:,1:3), 2);
bg_sum(:,1) = sum(bellargw(:,1:3), 2);
fs_sum(:,2) = sum(fiatshamir(:,4:8), 2);
bg_sum(:,2) = sum(bellargw(:,4:8), 2);
fs_sum(:,3) = sum(fiatshamir(:,9:13), 2);
bg_sum(:,3) = sum(bellargw(:,9:13), 2);
fs_sum(:,4) = sum(fiatshamir(:,14), 2);
bg_sum(:,4) = sum(bellargw(:,14), 2);


create_plot("fis", arg_list, fs_sum);
create_plot("bg", arg_list, bg_sum);

